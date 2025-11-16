pub mod print_help;
pub mod arguments;
pub mod calculation;
pub mod smpc_buffer;
pub mod runner;

use crate::helpers::arg_conf::Config;
use crate::helpers::welsib_stream::WelsibStream;
use crate::helpers::arg_key::Keypair;
use crate::smpc::response::handshake::HandshakeResponseAttributes;
use crate::smpc::response::send_slot::SendSlotResponseAttributes;
use crate::smpc::response::send_point::SendPointResponseAttributes;
use crate::smpc::response::receive_slot::ReceiveSlotResponseAttributes;
use crate::smpc::response::SMPCResponse;
use crate::smpc::slot::{Slot, SlotType};
use arguments::WelsibClientArguments;
use crate::smpc::request::handshake::HandshakeRequestAttributes;
use crate::smpc::request::send_slot::SendSlotRequestAttributes;
use crate::smpc::request::send_point::SendPointRequestAttributes;
use crate::smpc::request::receive_slot::ReceiveSlotRequestAttributes;
use crate::smpc::request::SMPCRequest;
// use crate::smpc::WelsibDtoInterface;
use crate::client::calculation::decode::Decode;
use crate::client::calculation::decode_key::DecodeKey;
use crate::smpc::point_type::PointType;
use crate::random::create_random_additive_parts;

use std::net::TcpStream;
use std::time::Duration;
use std::thread::sleep;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use calculation::Calculation;
use calculation::encode::Encode;
use smpc_buffer::SMPCBuffer;
use runner::Runner;
use welsib_u512_ec::point::Point;
use welsib_u512_ec::keys::{make_signing_key, welsib_make_verifying_key};
use welsib_u512_ec::sign::welsib_u512_sum;
use welsib_u512::u512::{U512, U512Add};
use welsib_u512_ec::elliptic_curve::x2_mod::x2_mod;
use welsib_u512_ec::elliptic_curve::EllipticCurve;
use welsib_u512_ec::agg_crypt::EllipticCurveCrypt;
use std::fs;
use std::path::PathBuf;

pub struct Client {
    config: Config,
    arguments: WelsibClientArguments,
    keypair: Keypair,
    value: u64,
    // random_nonce_sum: BigInt,
    // random_nonce_values: Option<Vec<BigInt>>,
    // random_nonce_slots: Option<BTreeMap<BigInt, Slot>>, // key: Point.x, value: Slot
    smpc_buffer: Arc<Mutex<SMPCBuffer>>,
    runners: Arc<Mutex<VecDeque<Runner>>>,
    planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>,
}

impl Client {
    pub fn new(config: &Config, arguments: &WelsibClientArguments, keypair: Keypair)  -> std::io::Result<Self> {
        // let random_nonce_sum = create_shifted_random();
        let runners = Arc::new(Mutex::new(VecDeque::new()));
        let planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let value = Self::decode_value(arguments, &keypair)?;
        Ok(Self {
            config: config.clone(),
            arguments: arguments.clone(),
            keypair,
            value,
            smpc_buffer: Arc::new(Mutex::new(SMPCBuffer::new())),
            runners,
            planned,
        })
    }

    pub fn run(&mut self) -> std::io::Result<(Point, Point)> {
        self.init_runners(self.arguments.get_concurrency())?; // Инициализация раннеров

        // Определение количества участников
        let pk_len = self.config.get_public_keys().len();
        if pk_len < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка: Участников не может быть меньше четырёх: (1) сумма = (2,3) два слагаемых и (4) контролёр.",
            ));
        }
        let participants = pk_len-1; // за исключением контролёра

        let self_position = if let Ok(self_position) = self.get_position(&self.keypair.get_public_key()) {
            self_position
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка: Не удалось определить собственную позицию на основе списка ключей из файла конфигурации.",
            ));
        };

        ///////////////////////////////////////////////////////////////////////////////
        let public_keys = self.config.get_public_keys()[..self.config.get_public_keys().len() - 1].to_vec();

        let mut sended_key_slots = vec![];
        if public_keys.len() > 0 {
            // Дополнительный ключ для объединения с RANGE proof
            let smpc_buffer_copy = self.smpc_buffer.clone();
            if let Ok(smpc_buffer) = &mut self.smpc_buffer.lock() {
                // println!("Step3");
                // TODO: добавить оптимизацию, не добавлять в план шифрование собственного слота
                smpc_buffer.create_range_key_additive_parts(participants, self.config.get_public_keys(), self.planned.clone(), smpc_buffer_copy)?;  // SlotType::Key
            }
            self.run_runners();

            // Отправка SlotType::Key слотов
            crate::dd(format!("Отправка SlotType::Key слотов\n{:?}", &participants), "key");
            loop {
                // if sended_key_slots.len() == public_keys.len() - 1 {
                if sended_key_slots.len() == public_keys.len() {
                    // println!("Step13(key)");
                    break;
                }
                for (i, p) in public_keys.iter().enumerate() {
                    // println!("Step14(key)");
                    // TODO: собственную часть range ключа не обязательно отправлять на сервер и получать с сервера
                    if sended_key_slots.contains(&i) /*|| self.keypair.get_public_key() == *p*/ {
                        // Игнорировать отправленные
                        // Игнорировать отправку на сервер собственного слота (для вычислений своей части)
                        continue;
                    }
                    if let Ok(smpc_buffer) = self.smpc_buffer.lock() {
                        // println!("Step15(key)");
                        // let slot = Some(additional_key_slots[i].clone()); // TODO: использовать smpc_buffer и методы
                        let slot = smpc_buffer.get_random_range_slot_by_public_key(p);
                        if let Some(slot) = slot {
                            // println!("Step16(key)");
                            crate::dd(format!("send_slot: {:?}\n{:x?}", &i, &p.x.get()[0]), "send_slot_key");
                            match self.send_slot(SlotType::Key, &slot, i, &self.keypair) {
                                Ok(()) => {
                                    // Слот отправлен успешно
                                    // crate::dd(format!("Слот SlotType::Key отправлен успешно {:#?}", &i), "key");
                                    sended_key_slots.push(i);
                                },
                                Err(e) => {
                                    crate::d(format!("Ошибка: отправка слота-ключа не увенчалась успехом и будет повторена\n{:?}", e));
                                    sleep(std::time::Duration::from_millis(10)); // TODO: attempts (counter)
                                },
                            };
                            // println!("Step18(key)");
                        }
                    }
                }
                // println!("Step19(key)");
            }

            // TODO: Получение SlotType::Key слотов остальных участников
            crate::dd(format!("Получение SlotType::Key слотов остальных участников"), "key");
            // ...
            // match self.receive_slot(SlotType::Key, position, &self.keypair) {
            // ...
            // let mut calc = DecodeKey::new(self.smpc_buffer.clone());
            // ...

            // ================================================================================
            // Получение Key слотов остальных клиентов
            // let public_keys = self.config.get_public_keys()[..self.config.get_public_keys().len() - 1].to_vec();
            let public_keys = self.config.get_public_keys()[..self.config.get_public_keys().len()].to_vec(); // не исключается ключ контролёра (не вычитается единица)
            let mut received_key_slots = vec![];
            loop {
                // sleep(std::time::Duration::from_millis(100)); // DEBUG: duration
                // println!("===========================");
                // if received_key_slots.len() == public_keys.len() - 1 {
                if received_key_slots.len() == public_keys.len() {
                    // println!("Step33");
                    // процесс выполнен, выйти из цикла
                    break;
                }
                for (position, public_key) in public_keys.iter().enumerate() {
                    // TODO: собственную часть range ключа не обязательно отправлять на сервер и получать с сервера
                    // if *public_key == self.keypair.get_public_key() {
                    //     // println!("Step31");
                    //     // Пропустить 
                    //     continue;
                    // }
                    if received_key_slots.contains(&position) {
                        // Не загружать загруженные слоты
                        continue;
                    }
                    // TODO: учитывать команду reset от других клиентов и сервера, начиная принимать слоты клиента и сервера снова (в зависимости типа ресета, определённого клиента или сервера)
                    crate::dd(format!("DEBUG: decode key"), "decode_key");
                    crate::dd(format!("receive_slot: {:?}\np:{:x?}\ns:{:x?}\n", &position, &public_key.x.get()[0], &self.keypair.get_secret_key().get()[0]), "receive_slot_key");
                    match self.receive_slot(SlotType::Key, position, &self.keypair) {
                        Ok(slot) => {
                            crate::dd(format!("DEBUG: decode key (slot):\n{:?}", &slot), "decode_key");
                            if let Ok(mut smpc_buffer) = self.smpc_buffer.lock() {
                                smpc_buffer.insert_key_slot(&slot);
                                received_key_slots.push(position);
                                // Добавить self.planned запланированное декодирование слота
                                if let Ok(mut planned) = self.planned.lock() {
                                    let mut calc = DecodeKey::new(self.smpc_buffer.clone());
                                    calc.set_slot(slot.clone());
                                    calc.set_slot_position(position);
                                    calc.set_decode_key(self.keypair.get_secret_key());
                                    planned.push_front(Box::new(calc));
                                    crate::dd(format!("Planned decode (pushed) {position}"), "decode_key");
                                    crate::dd(format!("Planned decode (pushed) {position}\n{:x?}", &public_key.x.get()[0]), "receive_slot_key");
                                }
                            } else {
                                crate::dd(format!("Ошибка: нет доступа к smpc_buffer"), "key");
                                sleep(std::time::Duration::from_millis(100));
                            }
                        },
                        Err(e) => {
                            crate::dd(format!("Ошибка: не удалось получить серверный Key слот\n{:?}\nposition: {position}\n", e), "key");
                            sleep(std::time::Duration::from_millis(100));
                        },
                    };
                }
            }

            crate::dd(format!("DEBUG: Загрузка с сервера Key слотов завершена успешно"), "key");

            // Запустить декодирование в параллельных процессах с использованием очереди свободных раннеров
            self.run_runners();

            // TODO: дождаться завершения декодирования

            crate::dd(format!("DEBUG: Декодирование Key слотов завершено успешно"), "key");
            // ================================================================================

            // TODO: Расшифровка и агрегация SlotType::Key в ключ предназначенный для использования в алгоритме слияния wsmpc с range proof
        }

        // if let Some(range_agg_key) = get_agg_received_key
        // TODO: smpc_buffer.set_random_nonce_sum(range_agg_key);
        // if let Ok(smpc_buffer) = &mut self.smpc_buffer.lock() {
        //     // TODO: Синхронизировать асинхронное выполнение вычислений
        //     crate::dd(format!("DEBUG: agg_received_key (before)"), "run");
        //     smpc_buffer.agg_received_key(self.config.get_public_keys());
        //     crate::dd(format!("DEBUG: agg_received_key (after)"), "run");
        // }

        loop {
            sleep(std::time::Duration::from_millis(100));
            if let Ok(smpc_buffer) = &mut self.smpc_buffer.lock() {
                crate::dd(format!("DEBUG agg_received_key:\n{:?}", &smpc_buffer.get_range_received_keys()), "agg_received_key");
                if let Some(range_received_keys) = &smpc_buffer.get_range_received_keys() {
                    crate::dd(format!("DEBUG agg_received_key:\n{:?}", &range_received_keys), "agg_received_key");
                    let mut keys: Vec<U512> = vec![];
                    if range_received_keys.len() == self.config.get_public_keys().len() {
                        for (_, key) in range_received_keys {
                            keys.push(key.clone());
                        }
                        // smpc_buffer.set_random_nonce_sum(welsib_u512_sum(range_received_keys.iter().map(|(_, v)| v.clone()).collect::<Vec<U512>>()));
                        crate::dd(format!("DEBUG set_random_nonce_sum:\n{:?}", &keys), "agg_received_key");
                        smpc_buffer.set_random_nonce_sum(welsib_u512_sum(keys));
                        break;
                    } else {
                        crate::dd(format!("DEBUG await: range_received_keys.len() == self.config.get_public_keys().len():\n{:?} == {:?}", &range_received_keys.len(), &self.config.get_public_keys().len()), "agg_received_key");
                        sleep(std::time::Duration::from_millis(100));
                    }
                } else {
                    crate::dd(format!("DEBUG agg_received_key (None):\n{:?}", &smpc_buffer.get_range_received_keys()), "agg_received_key");
                    sleep(std::time::Duration::from_millis(100));
                }
            } else {
                crate::dd(format!("DEBUG smpc_buffer (locked)"), "agg_received_key");
                sleep(std::time::Duration::from_millis(100));
            }
        }
        ///////////////////////////////////////////////////////////////////////////////

        // println!("Step1");
        if self.arguments.is_sum() {
            // println!("Step2");
            // если клиент - определяет сумму, а не слагаемое, то разместить на сервере контролёра в SMPCField индивидуальные случайные значения
            let smpc_buffer_copy = self.smpc_buffer.clone();
            if let Ok(smpc_buffer) = &mut self.smpc_buffer.lock() {
                // println!("Step3");
                // TODO: добавить оптимизацию, не добавлять в план шифрование собственного слота
                smpc_buffer.create_random_nonce_additive_parts(participants, self.config.get_public_keys(), self.planned.clone(), smpc_buffer_copy)?;  // SlotType::Main
            }

            // Выполнить клиентский рассчёт слотов нонса клиентам с предварительным индивидуальным шифрованием в зависимости от concurrency
            self.run_runners();

            // Отправить на сервер Main слоты для участников за исключением контролёра
            let mut sended_slots = vec![];
            // println!("Step11");
            if public_keys.len() > 0 {
                // Отправка SlotType::Main слотов
                loop {
                    sleep(std::time::Duration::from_millis(100));
                    // sleep(std::time::Duration::from_millis(100)); // DEBUG: duration
                    // println!("Step12");
                    if sended_slots.len() == public_keys.len() - 1 {
                        // println!("Step13");
                        break;
                    }
                    for (i, p) in public_keys.iter().enumerate() {
                        // println!("Step14");
                        if sended_slots.contains(&i) || self.keypair.get_public_key() == *p {
                            // Игнорировать отправленные
                            // Игнорировать отправку на сервер собственного слота (для вычислений своей части)
                            continue;
                        }
                        if let Ok(smpc_buffer) = self.smpc_buffer.lock() {
                            // println!("Step15");
                            let slot = smpc_buffer.get_random_nonce_slot_by_public_key(p);
                            if let Some(slot) = slot {
                                // println!("Step16");
                                match self.send_slot(SlotType::Main, &slot, i, &self.keypair) {
                                    Ok(()) => {
                                        // Слот отправлен успешно
                                        sended_slots.push(i);
                                    },
                                    Err(e) => {
                                        crate::d(format!("Ошибка: отправка слота не увенчалась успехом и будет повторена\n{:?}", e));
                                        sleep(std::time::Duration::from_millis(10)); // TODO: attempts (counter)
                                    },
                                };
                                // println!("Step18");
                            }
                        }
                    }
                    // println!("Step19");
                }
            }
        }

        // TODO: учесть, что во время синхронизации (получения слотов) некоторые клиенты могут быть перезапущенными и ранее полученные данные надо будет сбросить и получать снова

        // Получение серверного Controller слота
        loop {
            sleep(std::time::Duration::from_millis(100));
            // sleep(std::time::Duration::from_millis(100)); // DEBUG: duration
            match self.get_position(&self.keypair.get_public_key()) { // определить собственную позицию
                Ok(position) => {
                    match self.receive_slot(SlotType::Controller, position, &self.keypair) {
                        Ok(slot) => {
                            if let Ok(mut smpc_buffer) = self.smpc_buffer.lock() {
                                smpc_buffer.set_controller_random_slot(&slot);
                                // процесс выполнен, выйти из цикла
                                break;
                            } else {
                                crate::d(format!("Ошибка: нет доступа к smpc_buffer"));
                                sleep(std::time::Duration::from_millis(100));
                            }
                        },
                        Err(e) => {
                            crate::d(format!("Ошибка: не удалось получить серверный Controller слот\n{:?}", e));
                            sleep(std::time::Duration::from_millis(100));
                        },
                    };
                },
                Err(e) => {
                    return Err(e);
                },
            };
        }

        // Получение Main слота (владельца суммы) клиентом не являющимся владельцем суммы (т.е. запущенным без параметра --sum)
        if !self.arguments.is_sum() {
            loop {
                sleep(std::time::Duration::from_millis(100));
                // sleep(std::time::Duration::from_millis(100)); // DEBUG: duration
                match self.get_position(&self.keypair.get_public_key()) { // определить собственную позицию
                    Ok(position) => {
                        match self.receive_slot(SlotType::Main, position, &self.keypair) {
                            Ok(slot) => {
                                if let Ok(mut smpc_buffer) = self.smpc_buffer.lock() {
                                    smpc_buffer.set_sum_random_slot(&slot);
                                    // процесс выполнен, выйти из цикла
                                    break;
                                } else {
                                    crate::d(format!("Ошибка: нет доступа к smpc_buffer"));
                                    sleep(std::time::Duration::from_millis(100));
                                }
                            },
                            Err(_e) => {
                                // println!("Ошибка: не удалось получить серверный Controller слот\n{:?}", e);
                                sleep(std::time::Duration::from_millis(100));
                            },
                        };
                    },
                    Err(e) => {
                        return Err(e);
                    },
                };
            }
        }

        // Расшифровать полученные слоты (Controller и Main) для использования в вычислении разделяемой случайной суммы
        // println!("Step12");
        // если клиент - определяет сумму, а не слагаемое, то разместить на сервере контролёра в SMPCField индивидуальные случайные значения
        let smpc_buffer_copy = self.smpc_buffer.clone();
        if let Ok(smpc_buffer) = &mut self.smpc_buffer.lock() {
            // println!("Step13");
            // TODO: если клиент не --sum, то использовать Some(Main слот клиента-владельца суммы)
            // TODO: добавить оптимизацию, не добавлять в план шифрование собственного слота
            // TODO: запланировать декодирование слотов перед выполнением create_client_additive_parts
            // при этом слоты Controller и Main задекодить не через очереди и не порождая отдельных процессов, т.к. их всего два

            // c + m + r + v = s = s1 + s2 + ... + sn
            let m = if !self.arguments.is_sum() {
                // Декодировать Main-слот полученный от владельца суммы
                smpc_buffer.get_sum_random_slot_value(&self.keypair.get_secret_key())
            } else {
                // Вернуть собственный Main-value
                smpc_buffer.get_random_nonce_orig_value()
            };
            let c = smpc_buffer.get_controller_random_slot_value(&self.keypair.get_secret_key());
            let r = smpc_buffer.get_random_nonce_sum().unwrap();
            let v = U512::from_u64(self.value);

            // ========================================
            let (c_keys, c_points, confidential_value, rv) = smpc_buffer.do_range_proof(self.value).unwrap();
            // TODO: Использование новых формул для совместного доказательства с range proof
            // 1. Разделение значения на части для участников
            // 2. Обмен значениями в виде отдельных рандомизированных битов из доказательства диапазона
            // 3. Обмен дополнительными значениями
            // ========================================

            let agg_sum = if let Some(m) = m {
                if let Some(c) = c {
                    // v + r + m + c
                    welsib_u512_sum(vec![v, r, m, c]) // TODO: curve подключать из конфигурации (не хардкодить)
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "Ошибка: частичное значение серверного (контролёра) случайного числа не определено.",
                    ));
                }
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Ошибка: частичное значение владельца суммы не определено.",
                ));
            };
            smpc_buffer.set_random_client_sum(&agg_sum);
            let self_public_key = self.keypair.get_public_key();
            let another_keys: Vec<Point> = self.config.get_public_keys().iter().filter(|&v| *v != self_public_key).map(|v| v.clone()).collect();
            smpc_buffer.create_client_additive_parts(participants, &another_keys, self.planned.clone(), smpc_buffer_copy)?;
            // TODO: отправить эти числа на сервер для раздачи клиентам и запустить процесс получения таких слотов от остальных участников
        }

        // Выполнить клиентский рассчёт additive parts слотов клиентам с предварительным индивидуальным шифрованием в зависимости от concurrency
        self.run_runners();

        // Отправить на сервер Value слоты для участников
        let public_keys = self.config.get_public_keys().to_vec();
        let mut sended_slots = vec![];
        // println!("Step21");
        if public_keys.len() > 0 {
            loop {
                // sleep(std::time::Duration::from_millis(100)); // DEBUG: duration
                crate::d(format!("==========================="));
                crate::d(format!("Step22: {} {} {:?}", &sended_slots.len(), public_keys.len() - 1, &sended_slots));
                if sended_slots.len() == public_keys.len() - 1 {
                    // println!("Step23");
                    break;
                }
                let mut d = 0;
                for (i, p) in public_keys.iter().enumerate() {
                    // println!("Step24: {i} {d}");
                    if sended_slots.contains(&(i-d)) || self.keypair.get_public_key() == *p {
                        crate::d(format!("Continue: {:?} {:?} {:?}", &sended_slots, i-d, sended_slots.contains(&(i-d))));
                        crate::d(format!("KP: {:?} {:?}", &self.keypair.get_public_key().x, &p.x));
                        // Игнорировать отправленные
                        // Игнорировать отправку на сервер собственного слота (для вычислений своей части)
                        if self.keypair.get_public_key() == *p {
                            d = 1;
                        }
                        continue;
                    }
                    // println!("Step25: {i} {d}");
                    if let Ok(smpc_buffer) = &mut self.smpc_buffer.lock() {
                        let slot = smpc_buffer.get_client_slot_by_public_key(p);
                        // println!("DEBUG: Slot: {:?}", &slot);
                        if let Some(slot) = slot {
                            // println!("Step26");
                            match self.send_slot(SlotType::Value, &slot, i, &self.keypair) {
                                Ok(()) => {
                                    // Слот отправлен успешно
                                    sended_slots.push(i-d);
                                },
                                Err(e) => {
                                    crate::d(format!("Ошибка: отправка слота не увенчалась успехом и будет повторена\n{:?}", e));
                                    sleep(std::time::Duration::from_millis(100)); // TODO: attempts (counter)
                                },
                            };
                            // println!("Step28");
                        }
                    }
                }
                // println!("Step29");
                sleep(std::time::Duration::from_millis(100)); // снизить нагрузку на процессор при ожидании завершения вычислений раннерами
            }
        }

        crate::d(format!("DEBUG: Отправка на сервер Value слотов завершена успешно"));

        // Получение Value слотов остальных клиентов
        let public_keys = self.config.get_public_keys()[..self.config.get_public_keys().len() - 1].to_vec();
        let mut received_slots = vec![];
        loop {
            // sleep(std::time::Duration::from_millis(100)); // DEBUG: duration
            // println!("===========================");
            if received_slots.len() == public_keys.len() - 1 {
                // println!("Step33");
                // процесс выполнен, выйти из цикла
                break;
            }
            for (position, public_key) in public_keys.iter().enumerate() {
                if *public_key == self.keypair.get_public_key() {
                    // println!("Step31");
                    // Пропустить 
                    continue;
                }
                if received_slots.contains(&position) {
                    // Не загружать загруженные слоты
                    continue;
                }
                // TODO: учитывать команду reset от других клиентов и сервера, начиная принимать слоты клиента и сервера снова (в зависимости типа ресета, определённого клиента или сервера)
                match self.receive_slot(SlotType::Value, position, &self.keypair) {
                    Ok(slot) => {
                        if let Ok(mut smpc_buffer) = self.smpc_buffer.lock() {
                            smpc_buffer.insert_value_slot(&slot);
                            received_slots.push(position);
                            // Добавить self.planned запланированное декодирование слота
                            if let Ok(mut planned) = self.planned.lock() {
                                let mut calc = Decode::new(self.smpc_buffer.clone());
                                calc.set_slot(slot.clone());
                                calc.set_slot_position(position);
                                calc.set_decode_key(self.keypair.get_secret_key());
                                planned.push_front(Box::new(calc));
                                crate::d(format!("Planned decode (pushed) {position}"));
                            }
                        } else {
                            crate::d(format!("Ошибка: нет доступа к smpc_buffer"));
                            sleep(std::time::Duration::from_millis(100));
                        }
                    },
                    Err(e) => {
                        crate::d(format!("Ошибка: не удалось получить серверный Value слот\n{:?}", e));
                        sleep(std::time::Duration::from_millis(100));
                    },
                };
            }
        }

        crate::d(format!("DEBUG: Загрузка с сервера Value слотов завершена успешно"));

        // Запустить декодирование в параллельных процессах с использованием очереди свободных раннеров
        self.run_runners();

        crate::d(format!("DEBUG: Декодирование Value слотов завершено успешно"));

        // return Ok(());

        // Вычисление клиентских верификационных ключей Point из клиентских расшифрованных слотов и отправка их на сервер
        // TODO: добавить loop с лимитом attempts на отправку и учитывать вероятность поступления запроса reset на перерассчёт и переотправку данных для определённого клиента или сервера
        let mut is_point_matrix_sended = false;
        let mut is_point_list_sended = false;
        let mut solution_point_matrix = None;
        let mut solution_point_list = None;
        loop {
            // sleep(std::time::Duration::from_millis(100)); // DEBUG: duration
            // TODO: обработать получение статуса с сервера, если появилась команда reset, то запустить загрузку и пересчёт
            crate::d(format!("Process sending points:\n=============================="));
            // TODO: не вычислять повторно ранее вычисленные значения
            if let Ok(smpc_buffer) = self.smpc_buffer.lock() {
                // FIXME: make_value_matrix возвращает None
                if !is_point_matrix_sended {
                    if let Some(v) = smpc_buffer.make_value_matrix(self.config.get_public_keys().len()-1) {
                        let point_matrix = welsib_make_verifying_key(&v);
                        if let Some(p) = point_matrix {
                            match self.send_point(&p, PointType::Matrix, self_position, &self.keypair) {
                                Ok(()) => {
                                    crate::d(format!("Отправка клиентского ключа point_matrix совершена успешно"));
                                    is_point_matrix_sended = true;
                                    solution_point_matrix = Some(p);
                                },
                                Err(_e) => {
                                    crate::d(format!("Error: не удалось отправить point_matrix"));
                                    sleep(std::time::Duration::from_millis(100));
                                },
                            }
                        } else {
                            crate::d(format!("Error: не удалось создать point_matrix из make_value_matrix"));
                            sleep(std::time::Duration::from_millis(100));
                        }
                    } else {
                        // FIXME: клиент зацикливается на этой ошибке
                        crate::d(format!("Error: не удалось вычислить клиентский верификационный ключ"));
                        sleep(std::time::Duration::from_millis(100));
                    }
                }

                if !is_point_list_sended {
                    if let Some(v) = if self.arguments.is_sum() {
                        if let Some(random_nonce_orig_value) = smpc_buffer.get_random_nonce_orig_value() {
                            // Some(random_nonce_orig_value.clone()+&random_nonce_orig_value.clone())
                            let curve = EllipticCurve::make_curve_welsib();
                            x2_mod(&random_nonce_orig_value, &curve.p) // TODO: выяснить, curve.p или curve.q
                        } else {
                            None
                        }
                    } else {
                        smpc_buffer.make_value_list(U512::from_u64(self.value))
                    } {
                        let point_list = welsib_make_verifying_key(&v);
                        if let Some(p) = point_list {
                            match self.send_point(&p, PointType::List, self_position, &self.keypair) {
                                Ok(()) => {
                                    crate::d(format!("Отправка клиентского ключа point_list совершена успешно"));
                                    is_point_list_sended = true;
                                    solution_point_list = Some(p);
                                },
                                Err(_e) => {
                                    crate::d(format!("Error: не удалось отправить point_matrix"));
                                    sleep(std::time::Duration::from_millis(100));
                                },
                            }
                        } else {
                            crate::d(format!("Error: не удалось создать point_list из make_value_list"));
                            sleep(std::time::Duration::from_millis(100));
                        }
                    }
                }
            }
            if is_point_matrix_sended && is_point_list_sended {
                crate::d(format!("Условия выхода из цикла отправки ключенвых points выполнены успешно"));
                break;
            }
        }

        Ok((solution_point_matrix.unwrap(), solution_point_list.unwrap()))
    }

    // Инициализация раннеров (runner - отдельный параллельный процесс запускающий выполнение рассчётов calculation)
    fn init_runners(&self, count: usize) -> std::io::Result<()> {
        if count < 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка, раннеров должно быть не менее одного.",
            ));
        }
        for _i in 0..count {
            if let Ok(mut runners) = self.runners.lock() {
                runners.push_front(Runner::new(self.runners.clone()));
            }
        }
        Ok(())
    }

    fn run_runners(&self) {
        crate::dd(format!("Run runners:"), "run_runners");
        loop {
            crate::dd(format!("Step4"), "run_runners");
            if if let Ok(planned) = self.planned.lock() {
                crate::dd(format!("Step5 {:#?} {}", planned.len() > 0, &planned.len()), "run_runners");
                planned.len() > 0
            } else {
                crate::dd(format!("Step6"), "run_runners");
                false
            } {
                crate::dd(format!("Step7"), "run_runners");
                if let Some(mut runner) = self.runners.lock().unwrap().pop_back() {
                    crate::dd(format!("Step8 (RUN)"), "run_runners");
                    runner.run(self.planned.clone());
                } else {
                    crate::dd(format!("Step9"), "run_runners");
                    // подождать освобождение раннера
                    sleep(std::time::Duration::from_millis(100));
                }
            } else {
                crate::dd(format!("Step10"), "run_runners");
                break;
            }
        }
    }

    // Метод отправки Point-а (шифровать не обязательно, т.к. ключевой Point на сервере-контролёре)
    fn send_point(&self, point: &Point, point_type: PointType, client_index: usize, keypair: &Keypair) -> std::io::Result<()> {
        // Отправить запрос на сервер с АВТОРИЗАЦИЕЙ (с цифровой подписью)
        // при этом сгенерировать сервером уникальный id сессии с привязкой к времени сервера для авторизации (защита от подмены из кешированных старых данных)
        // безсессионный метод (интервалы как в API дистрибьютора смежного проекта), данные сессии не хранятся между запросами

        // Handshake request
        let attr = HandshakeRequestAttributes{};
        crate::d(format!("Attr JSON {}", &attr.to_json()));
        let smpc_handshake_request = SMPCRequest::new(
            String::from("handshake"),
            attr.to_json(),
        );
        let handshake_response = self.send_request(smpc_handshake_request)?;

        // Send point request
        let handshake_response_attributes = HandshakeResponseAttributes::from_json(&handshake_response.attributes);
        if let Some(handshake_response_attributes) = handshake_response_attributes {
            let point_frame = point.to_be_bytes();
            let request_attr = SendPointRequestAttributes::new(point_frame, client_index, handshake_response_attributes.nonce_sig, &keypair);
            crate::d(format!("DEBUG SendPointRequestAttributes:\n{:?}", &request_attr));
            // println!("SendPointRequestAttributes JSON {}", &request_attr.to_json::<SendPointRequestAttributes>());
            let smpc_send_point_request = SMPCRequest::new(
                String::from(format!("send_point_{}", point_type.to_string())),
                request_attr.to_json(),
            );
            let send_point_response = self.send_request(smpc_send_point_request)?;
            crate::d(format!("Send point response: {:?}", &send_point_response));
            let send_point_response_attributes = SendPointResponseAttributes::from_json(&send_point_response.attributes);
            if let Some(send_point_response_attributes) = send_point_response_attributes {
                // Убедиться, что подпись клиента в ответе соответствует актуальной подписи клиента в запросе (не MiTM, и не из кеша)
                if send_point_response_attributes.is_success(&request_attr.signature) {
                    // Success
                    return Ok(());
                }
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                format!("Ошибка: {:?}", send_point_response.attributes),
            ));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Ошибка: отправка слота не удалась.",
        ))
    }

    fn send_slot(&self, slot_type: SlotType, slot: &Slot, i: usize, keypair: &Keypair) -> std::io::Result<()> {
        // Отправить запрос на сервер с АВТОРИЗАЦИЕЙ (с цифровой подписью)
        // при этом сгенерировать сервером уникальный id сессии с привязкой к времени сервера для авторизации (защита от подмены из кешированных старых данных)
        // безсессионный метод (интервалы как в API дистрибьютора смежного проекта), данные сессии не хранятся между запросами

        // Handshake request
        let attr = HandshakeRequestAttributes{};
        // println!("Attr JSON {}", &attr.to_json::<HandshakeRequestAttributes>());
        let smpc_handshake_request = SMPCRequest::new(
            String::from("handshake"),
            attr.to_json(),
        );
        let handshake_response = self.send_request(smpc_handshake_request)?;

        // Send slot request
        let handshake_response_attributes = HandshakeResponseAttributes::from_json(&handshake_response.attributes);
        if let Some(handshake_response_attributes) = handshake_response_attributes {
            let slot_frame = slot.to_bytes();
            let client_index = if let Some(client_index) = self.config.get_public_keys().iter().position(|point| point == &keypair.get_public_key()) {
                client_index
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Ошибка: в конфигурационном файле со списком публичных ключей участников собственный публичный ключ не обнаружен.",
                ));
            };
            let request_attr = SendSlotRequestAttributes::new(slot_type, i, slot_frame, client_index, handshake_response_attributes.nonce_sig, &keypair);
            crate::d(format!("DEBUG SendSlotRequestAttributes:\n{:?}", &request_attr));
            // println!("SendSlotRequestAttributes JSON {}", &request_attr.to_json::<SendSlotRequestAttributes>());
            let smpc_send_slot_request = SMPCRequest::new(
                String::from("send"),
                request_attr.to_json(),
            );
            let send_slot_response = self.send_request(smpc_send_slot_request)?;
            crate::d(format!("Send slot response: {:?}", &send_slot_response));
            let send_slot_response_attributes = SendSlotResponseAttributes::from_json(&send_slot_response.attributes);
            if let Some(send_slot_response_attributes) = send_slot_response_attributes {
                // Убедиться, что подпись клиента в ответе соответствует актуальной подписи клиента в запросе (не MiTM, и не из кеша)
                if send_slot_response_attributes.is_success(&request_attr.signature) {
                    // Success
                    return Ok(());
                }
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                format!("Ошибка: {:?}", send_slot_response.attributes),
            ));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Ошибка: отправка слота не удалась.",
        ))
    }

    fn receive_slot(&self, slot_type: SlotType, i: usize, keypair: &Keypair) -> std::io::Result<Slot> {
        // Handshake request
        let attr = HandshakeRequestAttributes{};
        // println!("Attr JSON {}", &attr.to_json::<HandshakeRequestAttributes>());
        let smpc_handshake_request = SMPCRequest::new(
            String::from("handshake"),
            attr.to_json(),
        );
        let handshake_response = self.send_request(smpc_handshake_request)?;

        // Receive slot request
        let handshake_response_attributes = HandshakeResponseAttributes::from_json(&handshake_response.attributes);
        if let Some(handshake_response_attributes) = handshake_response_attributes {
            let client_index = if let Some(client_index) = self.config.get_public_keys().iter().position(|point| point == &keypair.get_public_key()) {
                client_index
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Ошибка: в конфигурационном файле со списком публичных ключей участников собственный публичный ключ не обнаружен.",
                ));
            };

            let request_attr = ReceiveSlotRequestAttributes::new(slot_type, i, client_index, handshake_response_attributes.nonce_sig, &keypair);
            crate::dd(format!("DEBUG ReceiveSlotRequestAttributes:\n{:?}", &request_attr), "receive_slot");
            // println!("ReceiveSlotRequestAttributes JSON {}", &request_attr.to_json::<ReceiveSlotRequestAttributes>());
            let smpc_receive_slot_request = SMPCRequest::new(
                String::from("receive"),
                request_attr.to_json(),
            );
            let receive_slot_response = self.send_request(smpc_receive_slot_request)?;
            crate::dd(format!("Receive slot response: {:?}", &receive_slot_response), "receive_slot");
            let receive_slot_response_attributes = ReceiveSlotResponseAttributes::from_json(&receive_slot_response.attributes);
            if let Some(receive_slot_response_attributes) = receive_slot_response_attributes {
                // Убедиться, что подпись клиента в ответе соответствует актуальной подписи клиента в запросе (не MiTM, и не из кеша)
                if receive_slot_response_attributes.is_success(&request_attr.signature) {
                    // Success
                    crate::dd(format!("DEBUG receive_slot_response_attributes:\n{:?}", &receive_slot_response_attributes), "receive_slot");
                    return Ok(receive_slot_response_attributes.get_slot());
                }
            }

            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                format!("Ошибка: {:?}", receive_slot_response.attributes),
            ));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Ошибка получения слота.",
        ))
    }

    fn send_request(&self, request: SMPCRequest) -> std::io::Result<SMPCResponse> {
        let addr = self.arguments.get_addr();

        // надо дождаться ответа
        let pauses = [0, 10, 100, 1000, 10000]; // in mills
        let mut attempts_request = 0; // счётчик попыток отправки данных

        loop {
            crate::dd(format!("Try connect..."), "send_request");
            match TcpStream::connect(&addr) {
                Ok(stream) => {
                    match stream.set_write_timeout(Some(Duration::from_secs(30))) {
                        Ok(()) => {
                            match stream.set_read_timeout(Some(Duration::from_secs(30))) {
                                Ok(()) => {
                                    let mut welsib_stream = WelsibStream {
                                        tcp_stream: Some(stream),
                                    };
                                    crate::dd(format!("DEBUG welsib_stream.write(&request.to_frame()):\n{:?}", &request.to_frame()), "send_request");
                                    welsib_stream.write(&request.to_frame())?; // request

                                    let mut attempts_response = 0; // счётчик попыток приёма данных

                                    loop {
                                        let response = welsib_stream.read(); // response
                                        if let Some(frame) = &response {
                                            crate::dd(format!("Response (frame): {:?}", &frame), "send_request");
                                            let response = SMPCResponse::from_frame(frame);
                                            crate::dd(format!("Response: {:#?}", &response), "send_request");
                                            if let Some(response) = response {
                                                let public_keys = self.config.get_public_keys();
                                                let verify_key = public_keys[public_keys.len()-1].clone(); // последний ключ конфига -- публичный ключ контролёра (аудитора, проверяющего)
                                                if response.verify(&verify_key) {
                                                    return Ok(response);
                                                } else {
                                                    crate::dd(format!("Response is not verified"), "send_request");
                                                }
                                            } else {
                                                crate::dd(format!("Response is None"), "send_request");
                                            }
                                        } else {
                                            crate::dd(format!("Empty response"), "send_request");
                                        }
                                        sleep(Duration::from_millis(pauses[attempts_response]));
                                        if attempts_response < 4 {
                                            attempts_response += 1;
                                        } else {
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::Interrupted,
                                                "Ошибка, сервер не вернул ответ на запрос за разумное время (inner)",
                                            ));
                                        }
                                        // try read after 0, 10, 100, 1000 or 10000 milleseconds (after 4 attempts try every 10 sec)
                                    }
                                }
                                Err(e) => {
                                    crate::dd(format!("Error: TcpStream set read timeout: {:#?}", e), "send_request");
                                }
                            };
                        }
                        Err(e) => {
                            crate::dd(format!("Error: TcpStream set write timeout: {:#?}", e), "send_request");
                        }
                    };
                }
                Err(e) => {
                    crate::dd(format!("Error connection: {:#?}", e), "send_request");
                }
            }

            sleep(Duration::from_millis(pauses[attempts_request]));
            if attempts_request < 4 {
                attempts_request += 1;
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Ошибка, сервер не вернул ответ на запрос за разумное время (outer)",
                ));
            }
            // try read after 0, 10, 100, 1000 or 10000 milleseconds (after 4 attempts try every 10 sec)
        }
    }

    fn get_position(&self, public_key: &Point) -> std::io::Result<usize> {
        if let Some(client_index) = self.config.get_public_keys().iter().position(|point| point == public_key) {
            Ok(client_index)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка: в конфигурационном файле со списком публичных ключей участников собственный публичный ключ не обнаружен.",
            ));
        }
    }

    fn decode_value(arguments: &WelsibClientArguments, keypair: &Keypair) -> std::io::Result<u64> {
        let curve = EllipticCurve::make_curve_welsib();

        // Чтение файла с данными
        let filename = arguments.get_value_file_name();
        if filename.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidFilename,
                "Имя файла не может быть пустым",
            ));
        }
        let path = PathBuf::from(filename);
        if !fs::exists(&path)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Файл {:?} не найден", path),
            ));
        }
        let encrypted_data = fs::read(&path)?;
        let decrypted_data = curve.agg_decrypt(&encrypted_data, &keypair.get_secret_key());

        Ok(match String::from_utf8(decrypted_data) {
            Ok(s) => {
                match s.trim().parse::<u64>() {
                    Ok(number) => {
                        number
                    },
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Ошибка преобразования строкового value в u64"),
                        ));
                    },
                }
            },
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Ошибка преобразования value из массива байт в строку"),
                ));
            }
        })
    }
}