use crate::smpc::slot::{Slot, SlotType};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::helpers::shifted_random::create_shifted_random;
// use crate::server::context::calculation::encode::Encode;
use crate::random::create_random_additive_parts;
use crate::client::Calculation;
use crate::client::Encode;
use welsib_u512_ec::sign::welsib_u512_sum;
use welsib_u512::u512::{U512, U512Add};
use welsib_u512_ec::point::Point;
use welsib_u512_ec::elliptic_curve::x2_mod::x2_mod;
use welsib_u512_ec::elliptic_curve::EllipticCurve;
use std::thread::sleep;

pub struct SMPCBuffer {
    // ключи range proof
    random_range_key: U512,
    random_range_key_parts: Option<Vec<U512>>,
    range_key_slots: Option<BTreeMap<U512, Slot>>,
    range_recieved_slots: Option<Vec<Slot>>,
    range_received_keys: Option<BTreeMap<usize, U512>>,

    // ключи суммы
    random_nonce_sum: Option<U512>,
    random_nonce_orig_values: Option<Vec<U512>>,
    random_nonce_orig_slots: Option<BTreeMap<U512, Slot>>, // key: Point.x, value: Slot
    controller_random_slot: Option<Slot>, // слот контролёра (сервера проверяющего)
    controller_random_slot_value: Option<U512>, // расшифрованное значение слота (TOSO: при reset надо сбрасывать в None)
    sum_random_slot: Option<Slot>, // основной слот от владельца всей суммы, если этот клиент владелец суммы, то вместо sum_random_slot использовать random_nonce_orig_values.last()
    sum_random_slot_value: Option<U512>, // расшифрованное значение слота (TOSO: при reset надо сбрасывать в None)
    // TODO: матрица
    // TODO: список
    random_client_sum: Option<U512>,
    random_client_orig_values: Option<Vec<U512>>,
    random_client_orig_slots: Option<BTreeMap<U512, Slot>>, // key: Point.x, value: Slot

    // agg_sum: Option<U512>, // сумма Controller + Main + Random + Value для разделения на смешанные случайные значения с исходным
    // agg_values: Option<Vec<U512>>,
    // agg_slots: Option<BTreeMap<U512, Slot>>,
    received_values: Option<BTreeMap<usize, U512>>,
    received_slots: Option<Vec<Slot>>,
}

impl SMPCBuffer {
    pub fn new() -> Self {
        // let random_nonce_sum = create_shifted_random(); // устанавливается из результата range proof
        let random_range_key = create_shifted_random();
        Self {
            random_range_key,
            random_range_key_parts: None,
            range_key_slots: None,
            range_recieved_slots: None,
            range_received_keys: None,
            //
            random_nonce_sum: None,
            random_nonce_orig_values: None,
            random_nonce_orig_slots: None,
            controller_random_slot: None,
            controller_random_slot_value: None,
            sum_random_slot: None,
            sum_random_slot_value: None,
            random_client_sum: None,
            random_client_orig_values: None,
            random_client_orig_slots: None,
            // agg_sum: None,
            // agg_values: None,
            // agg_slots: None,
            received_values: None,
            received_slots: None,
        }
    }

    pub fn create_range_key_additive_parts(&mut self, participants: usize, public_keys: &Vec<Point>, planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>, smpc_buffer: Arc<Mutex<SMPCBuffer>>) -> std::io::Result<()> {
        if let Some(parts) = create_random_additive_parts(&self.random_range_key, participants) {
            // зашифровать parts для каждого участника используя параллельных воркеров runner, planned очереди и разместить в smpc_field в соответствующих слотах
            self.random_range_key_parts = Some(parts);
            // добавить в очередь для параллельного шифрования
            if let Ok(mut planned) = planned.lock() {
                if let Some(random_range_key_parts) = &mut self.random_range_key_parts {
                    if public_keys.len() < random_range_key_parts.len() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "Ошибка: недостаточно публичных ключей в конфигурации",
                        ));
                    }
                    for (i, item) in random_range_key_parts.iter().enumerate() {
                        let mut calc = Encode::new(smpc_buffer.clone());
                        calc.set_slot_type(SlotType::Key);
                        calc.set_value(item.clone());
                        calc.set_public_key(public_keys[i].clone());
                        planned.push_front(Box::new(calc));
                        // println!("Planned (pushed) {}", &i);
                    }
                }
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка: отсутствуют участники или их количество меньше трёх",
            ));
        }

        Ok(())
    }

    pub fn create_random_nonce_additive_parts(&mut self, participants: usize, public_keys: &Vec<Point>, planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>, smpc_buffer: Arc<Mutex<SMPCBuffer>>) -> std::io::Result<()> {
        if let Some(random_nonce_sum) = self.random_nonce_sum {
            if let Some(parts) = create_random_additive_parts(&random_nonce_sum, participants) {
                // зашифровать parts для каждого участника используя параллельных воркеров runner, planned очереди и разместить в smpc_field в соответствующих слотах
                self.random_nonce_orig_values = Some(parts);
                // добавить в очередь для параллельного шифрования
                if let Ok(mut planned) = planned.lock() {
                    if let Some(random_nonce_values) = &mut self.random_nonce_orig_values {
                        if public_keys.len() < random_nonce_values.len() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Interrupted,
                                "Ошибка: недостаточно публичных ключей в конфигурации",
                            ));
                        }
                        for (i, item) in random_nonce_values.iter().enumerate() {
                            let mut calc = Encode::new(smpc_buffer.clone());
                            calc.set_slot_type(SlotType::Main);
                            calc.set_value(item.clone());
                            calc.set_public_key(public_keys[i].clone());
                            planned.push_front(Box::new(calc));
                            // println!("Planned (pushed) {}", &i);
                        }
                    }
                }
                // push_computation (planned) для runners
                // println!("Секретные ключи нонс клиента владельца суммы: {:?}", &self.random_nonce_orig_values);
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Ошибка: отсутствуют участники или их количество меньше трёх",
                ));
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка: не установлено значение random_nonce_sum",
            ));
        }

        Ok(())
    }

    pub fn create_client_additive_parts(&mut self, participants: usize, public_keys: &Vec<Point>, planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>, smpc_buffer: Arc<Mutex<SMPCBuffer>>) -> std::io::Result<()> {
        if let Some(agg_sum) = &self.random_client_sum {
            if let Some(parts) = create_random_additive_parts(agg_sum, participants) {
                // println!("Additive parts: {:?}", &parts);
                // зашифровать parts для каждого участника используя параллельных воркеров runner, planned очереди и разместить в smpc_field в соответствующих слотах
                self.random_client_orig_values = Some(parts);
                // добавить в очередь для параллельного шифрования
                if let Ok(mut planned) = planned.lock() {
                    if let Some(random_client_orig_values) = &mut self.random_client_orig_values {
                        if public_keys.len() < random_client_orig_values.len() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Interrupted,
                                "Ошибка: недостаточно публичных ключей в конфигурации",
                            ));
                        }
                        for (i, item) in random_client_orig_values.iter().enumerate() {
                            let mut calc = Encode::new(smpc_buffer.clone());
                            calc.set_slot_type(SlotType::Value);
                            calc.set_value(item.clone());
                            calc.set_public_key(public_keys[i].clone());
                            planned.push_front(Box::new(calc));
                            // println!("Planned (pushed) {}", &i);
                        }
                    }
                }
                // push_computation (planned) для runners
                // println!("Секретные ключи нонс клиента владельца суммы: {:?}", &self.random_nonce_orig_values);
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Ошибка: отсутствуют участники или их количество меньше трёх",
                ));
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка: агрегированная сумма не готова",
            ));
        }

        Ok(())
    }

    pub fn insert_random_nonce_slot(&mut self, public_key: Point, slot: Slot) {
        if self.random_nonce_orig_slots.is_none() {
            self.random_nonce_orig_slots = Some(BTreeMap::new());
        }
        if let Some(random_nonce_orig_slots) = &mut self.random_nonce_orig_slots {
            random_nonce_orig_slots.insert(public_key.x, slot);
        }
    }

    pub fn insert_client_slot(&mut self, public_key: Point, slot: Slot) {
        if self.random_client_orig_slots.is_none() {
            self.random_client_orig_slots = Some(BTreeMap::new());
        }
        if let Some(random_client_orig_slots) = &mut self.random_client_orig_slots {
            random_client_orig_slots.insert(public_key.x, slot);
        }
    }

    pub fn insert_range_slot(&mut self, public_key: Point, slot: Slot) {
        if self.range_key_slots.is_none() {
            self.range_key_slots = Some(BTreeMap::new());
        }
        if let Some(range_key_slots) = &mut self.range_key_slots {
            range_key_slots.insert(public_key.x, slot);
        }
    }

    pub fn insert_received_value(&mut self, slot_position: usize, value: U512) {
        if self.received_values.is_none() {
            self.received_values = Some(BTreeMap::new());
        }
        if let Some(received_values) = &mut self.received_values {
            received_values.insert(slot_position, value);
        }
    }

    pub fn insert_received_key(&mut self, slot_position: usize, key: U512) {
        if self.range_received_keys.is_none() {
            self.range_received_keys = Some(BTreeMap::new());
        }
        if let Some(range_received_keys) = &mut self.range_received_keys {
            range_received_keys.insert(slot_position, key);
        }
    }

    pub fn get_range_received_keys(&self) -> &Option<BTreeMap<usize, U512>> {
        &self.range_received_keys
    }

    // pub fn agg_received_key(&mut self, public_keys: &Vec<Point>) {
    //     crate::dd(format!("DEBUG agg_received_key:\n{:?}", &self.range_received_keys), "agg_received_key");
    //     loop {
    //         if let Some(range_received_keys) = &self.range_received_keys {
    //             crate::dd(format!("DEBUG agg_received_key:\n{:?}", &range_received_keys), "agg_received_key");
    //             let mut keys: Vec<U512> = vec![];
    //             if range_received_keys.len() == public_keys.len() {
    //                 for (_, key) in range_received_keys {
    //                     keys.push(key.clone());
    //                 }
    //                 // self.set_random_nonce_sum(welsib_u512_sum(range_received_keys.iter().map(|(_, v)| v.clone()).collect::<Vec<U512>>()));
    //                 crate::dd(format!("DEBUG set_random_nonce_sum:\n{:?}", &keys), "agg_received_key");
    //                 self.set_random_nonce_sum(welsib_u512_sum(keys));
    //                 break;
    //             } else {
    //                 crate::dd(format!("DEBUG await: range_received_keys.len() == public_keys.len():\n{:?} == {:?}", &range_received_keys.len(), &public_keys.len()), "agg_received_key");
    //                 sleep(std::time::Duration::from_millis(100));
    //             }
    //         } else {
    //             crate::dd(format!("DEBUG agg_received_key (None):\n{:?}", &self.range_received_keys), "agg_received_key");
    //             sleep(std::time::Duration::from_millis(100));
    //         }
    //     }
    // }

    pub fn get_random_nonce_slot_by_public_key(&self, public_key: &Point) -> Option<Slot> {
        if let Some(random_nonce_orig_slots) = &self.random_nonce_orig_slots {
            if let Some(slot) = random_nonce_orig_slots.get(&public_key.x) {
                Some(slot.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_random_range_slot_by_public_key(&self, public_key: &Point) -> Option<Slot> {
        if let Some(range_key_slots) = &self.range_key_slots {
            if let Some(slot) = range_key_slots.get(&public_key.x) {
                Some(slot.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_client_slot_by_public_key(&self, public_key: &Point) -> Option<Slot> {
        if let Some(random_client_orig_slots) = &self.random_client_orig_slots {
            if let Some(slot) = random_client_orig_slots.get(&public_key.x) {
                Some(slot.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn set_controller_random_slot(&mut self, slot: &Slot) {
        self.controller_random_slot = Some(slot.clone());
    }

    pub fn set_sum_random_slot(&mut self, slot: &Slot) {
        self.sum_random_slot = Some(slot.clone());
    }

    pub fn set_random_client_sum(&mut self, random_client_sum: &U512) {
        self.random_client_sum = Some(random_client_sum.clone());
    }

    pub fn insert_value_slot(&mut self, slot: &Slot) {
        if let Some(received_slots) = &mut self.received_slots {
            received_slots.push(slot.clone());
        } else {
            self.received_slots = Some(vec![slot.clone()]);
        }
    }

    pub fn insert_key_slot(&mut self, slot: &Slot) {
        if let Some(range_recieved_slots) = &mut self.range_recieved_slots {
            range_recieved_slots.push(slot.clone());
        } else {
            self.range_recieved_slots = Some(vec![slot.clone()]);
        }
    }

    pub fn get_random_nonce_sum(&self) -> Option<U512> {
        self.random_nonce_sum.clone()
    }

    pub fn set_random_nonce_sum(&mut self, random_nonce_sum: U512) {
        self.random_nonce_sum = Some(random_nonce_sum)
    }

    // Возвращает собственное Main значение владельца суммы
    pub fn get_random_nonce_orig_value(&self) -> Option<U512> {
        if let Some(random_nonce_orig_values) = &self.random_nonce_orig_values {
            Some(random_nonce_orig_values[random_nonce_orig_values.len()-1].clone())
        } else {
            None
        }
    }

    pub fn get_sum_random_slot_value(&mut self, decrypt_key: &U512) -> Option<U512> {
        if let Some(sum_random_slot) = &self.sum_random_slot {
            self.sum_random_slot_value = Some(sum_random_slot.decrypt(decrypt_key));
            self.sum_random_slot_value.clone()
        } else {
            None
        }
    }

    pub fn get_controller_random_slot_value(&mut self, decrypt_key: &U512) -> Option<U512> {
        if let Some(controller_random_slot) = &self.controller_random_slot {
            self.controller_random_slot_value = Some(controller_random_slot.decrypt(decrypt_key));
            self.controller_random_slot_value.clone()
        } else {
            None
        }
    }

    pub fn make_value_matrix(&self, client_count: usize) -> Option<U512> {
        // FIXME: выявить наличие ошибок в этом методе
        if let Some(received_values) = &self.received_values {
            let mut keys = vec![];
            for i in 0..client_count {
                if let Some(v) = received_values.get(&i) {
                    keys.push(v.clone());
                }
            }
            if keys.len() != client_count-1 {
                // println!("DEBUG (make_value_matrix: keys.len() != client_count-1): {:?}", &keys);
                None
            } else {
                Some(welsib_u512_sum(keys))
            }
        } else {
            // println!("DEBUG (make_value_matrix: self.received_values is None)");
            None
        }
    }

    pub fn make_value_list(&self, value: U512) -> Option<U512> {
        let curve = EllipticCurve::make_curve_welsib(); // TODO: определять на основе информации из файла конфигурации
        // p = r + 2 * n + c + 2 * v
        // c: self.get_controller_random_slot_value()
        // r: self.get_random_nonce_sum()
        // n: self.get_sum_random_slot_value()
        // v: value
        if let Some(controller_random_slot_value) = &self.controller_random_slot_value {
            if let Some(sum_random_slot_value) = &self.sum_random_slot_value {
                let keys = [
                    controller_random_slot_value.clone(), // c
                    self.get_random_nonce_sum().unwrap(), // r
                    x2_mod(&sum_random_slot_value, &curve.p).unwrap(), // n
                    x2_mod(&value, &curve.p).unwrap(), // v
                ].to_vec();
                Some(welsib_u512_sum(keys))
            } else {
                if let Some(random_nonce_orig_values) = &self.random_nonce_orig_values {
                    if let Some(random_nonce_orig_values_last) = random_nonce_orig_values.get(random_nonce_orig_values.len()-1) {
                        let keys = [
                            controller_random_slot_value.clone(), // c
                            self.get_random_nonce_sum().unwrap(), // r
                            x2_mod(&random_nonce_orig_values_last, &curve.p).unwrap(), // n
                            x2_mod(&value, &curve.p).unwrap(), // v
                        ].to_vec();
                        Some(welsib_u512_sum(keys))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> Option<bool> {
        // TODO: когда значения всех сторон рассчитаны,
        // выдать true или false в зависимости от результата сравнения
        // значений от матрицы с значениями от списка, иначе выдать None
        None
    }
}
