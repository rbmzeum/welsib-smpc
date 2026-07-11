use crate::certificate::Certificate;
use crate::smpc::slot::{Slot, SlotType};
use std::collections::{BTreeMap, VecDeque, HashMap};
use std::sync::{Arc, Mutex};

use crate::helpers::shifted_random::create_shifted_random;
use crate::server::context::calculation::encode::Encode;
use crate::random::create_random_additive_parts;
use crate::server::context::calculation::Calculation;
use crate::helpers::arg_key::Keypair;
use crate::hash::hash;
use crate::range_prove::BitProve;
use welsib_u512_ec::sign::welsib_sign;
use welsib_u512_ec::sign::welsib_point_sum;
use welsib_u512_ec::sign::EllipticCurveSign;
use welsib_u512_ec::keys::welsib_make_verifying_key;
use welsib_u512_ec::point::Point;
use welsib_u512::u512::U512;
use welsib_u512_ec::sign::welsib_u512_sum;
use crate::range_prove::range_point_from_bit_proofs;
use welsib_u512_ec::elliptic_curve::EllipticCurve;
use welsib_u512_ec::keys::make_signing_key;
use welsib_u512_ec::keys::make_verifying_key;

#[derive(Debug)]
pub struct SMPCField {
    h_main: Option<Point>,
    client_h_list: Vec<Point>, // Список клиентских h-точек для верификации

    // ключи range proof (server)
    random_control_range_key: U512,
    random_control_range_key_parts: Option<Vec<U512>>,
    random_client_range_key_slots: BTreeMap<U512, BTreeMap<usize, Slot>>,

    // серверные ключи контролёра
    random_control_sum: U512,
    random_control_values: Vec<U512>,
    random_control_slots: BTreeMap<U512, Slot>, // key: Point.x, value: Slot
    // ключи клиентов
    client_slots: BTreeMap<U512, BTreeMap<usize, Slot>>,
    main_client_slots: BTreeMap<U512, Slot>,
    matrix_points: BTreeMap<U512, Point>,
    list_points: BTreeMap<U512, Point>,
    range_verification_key_points: BTreeMap<U512, Point>,

    // Для хранения отдельных битпруфов по индексам (если приходят по одному, 128 BitProve от каждого клиента)
    bit_proofs_parts: BTreeMap<U512, BTreeMap<usize, BitProve>>,
}

impl SMPCField {
    pub fn new() -> Self {
        let random_control_sum = create_shifted_random(); // устанавливается из результата range proof
        let random_control_range_key = create_shifted_random();
        Self {
            h_main: None,
            client_h_list: Vec::new(),
            random_control_range_key,
            random_control_range_key_parts: None,
            random_client_range_key_slots: BTreeMap::new(),
            random_control_sum,
            random_control_values: vec![],
            random_control_slots: BTreeMap::new(),
            client_slots: BTreeMap::new(),
            main_client_slots: BTreeMap::new(),
            matrix_points: BTreeMap::new(),
            list_points: BTreeMap::new(),
            range_verification_key_points: BTreeMap::new(),
            bit_proofs_parts: BTreeMap::new(),
        }
    }

    // Отладочные методы
    pub fn set_random_control_sum_debug(&mut self, random_control_sum: U512) {
        self.random_control_sum = random_control_sum
    }

    pub fn set_random_control_values_debug(&mut self, random_control_values: Vec<U512>) {
        self.random_control_values = random_control_values
    }

    pub fn set_random_control_slots_debug(&mut self, random_control_slots: BTreeMap<U512, Slot>) {
        self.random_control_slots = random_control_slots
    }

    pub fn set_client_slots_debug(&mut self, client_slots: BTreeMap<U512, BTreeMap<usize, Slot>>) {
        self.client_slots = client_slots
    }

    pub fn set_main_client_slots_debug(&mut self, main_client_slots: BTreeMap<U512, Slot>) {
        self.main_client_slots = main_client_slots
    }

    pub fn set_matrix_points_debug(&mut self, matrix_points: BTreeMap<U512, Point>) {
        self.matrix_points = matrix_points
    }

    pub fn set_list_points_debug(&mut self, list_points: BTreeMap<U512, Point>) {
        self.list_points = list_points
    }

    pub fn set_range_verification_key_points_debug(&mut self, range_verification_key_points: BTreeMap<U512, Point>) {
        self.range_verification_key_points = range_verification_key_points
    }
    // END DEBUG

    /// Генерирует ключ контролёра для присоединения проверки range proof
    /// 
    /// # Аргументы
    /// - `n`: количество частей для разбиения ключа (обычно PARTS+1)
    /// 
    /// # Возвращает
    /// Кортеж из трёх элементов:
    /// 1. Основной секретный ключ контролёра (U512)
    /// 2. Публичный ключ/точку для верификации (Point)
    /// 3. Вектор аддитивных частей ключа для распределения между участниками (Vec<U512>)
    pub fn make_key_control(&mut self, n: usize) -> Vec<U512> {
        // Создаём кривую для операций с эллиптической криптографией
        let curve = EllipticCurve::make_curve_welsib();
        
        // 1. Генерация случайного секретного ключа контролёра
        // Аналогично create_random() из тестового кода
        let kc_secret_main = make_signing_key(&curve);
        
        // 2. Создание верификационного ключа (публичной точки)
        let h_main = make_verifying_key(&curve, &kc_secret_main)
            .expect("Failed to create verifying key for controller");
        
        // 3. Разделение ключа на аддитивные части
        let kc_secret_main_parts = create_random_additive_parts(&kc_secret_main, n)
            .expect("Failed to create additive parts for controller key");
        
        // Сохраняем сгенерированные данные в структуру SMPCField
        // для дальнейшего использования в сетевом протоколе
        self.random_control_range_key = kc_secret_main.clone();
        self.random_control_range_key_parts = Some(kc_secret_main_parts.clone());
        self.h_main = Some(h_main.clone()); // Сохраняем публичный ключ
        
        kc_secret_main_parts
    }

    /// Возвращает публичную точку (верификационный ключ) контролёра для range proof
    /// 
    /// # Возвращает
    /// - `Some(Point)`: если ключ был сгенерирован через `make_key_control`
    /// - `None`: если ключ ещё не был сгенерирован
    pub fn get_h_main(&self) -> Option<Point> {
        self.h_main.clone()
    }

    pub fn create_range_key_additive_parts(&mut self, participants: usize, public_keys: &Vec<Point>, planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>, smpc_field: Arc<Mutex<SMPCField>>) -> std::io::Result<()> {
        if let Some(parts) = create_random_additive_parts(&self.random_control_range_key, participants) {
            // зашифровать parts для каждого участника используя параллельных воркеров runner, planned очереди и разместить в smpc_field в соответствующих слотах
            self.random_control_range_key_parts = Some(parts);
            // добавить в очередь для параллельного шифрования
            if let Ok(mut planned) = planned.lock() {
                if let Some(random_control_range_key_parts) = &mut self.random_control_range_key_parts {
                    if public_keys.len() < random_control_range_key_parts.len() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "Ошибка: недостаточно публичных ключей в конфигурации",
                        ));
                    }
                    for (i, item) in random_control_range_key_parts.iter().enumerate() {
                        let mut calc = Encode::new(smpc_field.clone());
                        calc.set_slot_type(SlotType::Key);
                        calc.set_value(item.clone());
                        calc.set_public_key(public_keys[i].clone());
                        // calc.set_public_key(public_keys[public_keys.len()-1].clone()); // Ключ контролёра
                        calc.set_control_public_key(public_keys[public_keys.len()-1].clone());
                        calc.set_index(i);
                        // calc.set_index(public_keys.len()-1);
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

    pub fn create_random_additive_parts(&mut self, participants: usize, public_keys: &Vec<Point>, planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>, smpc_field: Arc<Mutex<SMPCField>>) -> std::io::Result<()> {
        if let Some(parts) = create_random_additive_parts(&self.random_control_sum, participants) {
            // зашифровать parts для каждого участника используя параллельных воркеров runner, planned очереди и разместить в smpc_field в соответствующих слотах
            self.random_control_values = parts;
            // добавить в очередь для параллельного шифрования
            if let Ok(mut planned) = planned.lock() {
                if public_keys.len() < self.random_control_values.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "Ошибка: недостаточно публичных ключей в конфигурации",
                    ));
                }
                for (i, item) in self.random_control_values.iter().enumerate() {
                    let mut calc = Encode::new(smpc_field.clone());
                    calc.set_slot_type(SlotType::Controller);
                    calc.set_value(item.clone());
                    calc.set_public_key(public_keys[i].clone());
                    planned.push_front(Box::new(calc));
                    // println!("Planned (pushed) {}", &i);
                }
            }
            // push_computation (planned) для runners
            // println!("Секретные ключи контролёра: {:?}", &self.random_control_values);
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка: отсутствуют участники или их количество меньше трёх",
            ));
        }

        Ok(())
    }

    pub fn set_random_client_range_key_slot(&mut self, client_public_key: Point, index: usize, slot: Slot) {
        self.random_client_range_key_slots
            .entry(client_public_key.x)
            .or_insert_with(BTreeMap::new)
            .insert(index, slot);
    }

    pub fn get_random_client_range_key_slot(&self, client_public_key: Point, index: usize) -> Option<&Slot> {
        crate::dd(format!("DEBUG SlotType::Key (get_random_client_range_key_slots, client_public_key, index):\n{:?}\n{:?}", &client_public_key, &index), "receive_slot");
        crate::dd(format!("DEBUG SlotType::Key (random_client_range_key_slots):\n{:?}", &self.random_client_range_key_slots), "receive_slot");
        self.random_client_range_key_slots
            .get(&client_public_key.x)
            .and_then(|inner_map| inner_map.get(&index))
    }

    // pub fn set_random_control_range_key_slot(&mut self, public_key: Point, slot: Slot) {
    //     // self.random_control_range_key_slots.insert(public_key.x, slot);
    //     crate::dd(format!("DEBUG SlotType::Key (set_random_control_range_key_slot):\n{:?}", &self.random_client_range_key_slots), "set_random_control_range_key_slot");
    //     if let Some(random_control_range_key_parts) = &self.random_control_range_key_parts {
    //         let index = random_control_range_key_parts.len();
    //         // TODO:
    //         // public_key - для кого (из этого вычисляется индекс)
    //         // вместо public_key в set_random_client_range_key_slot использовать controller_public_key
    //         self.set_random_client_range_key_slot(public_key, index, slot);
    //     }
    // }

    // pub fn get_random_control_range_key_slot(&self, public_key: Point) -> Option<&Slot> {
    //     // TODO: 
    //     // self.random_control_range_key_slots.get(&public_key.x)
    //     crate::dd(format!("DEBUG SlotType::Key (get_random_control_range_key_slot, public_key):\n{:#?}", &public_key), "receive_slot");
    //     if let Some(random_control_range_key_parts) = &self.random_control_range_key_parts {
    //         let index = random_control_range_key_parts.len();
    //         crate::dd(format!("DEBUG SlotType::Key (get_random_control_range_key_slot, index):\n{:#?}", &index), "receive_slot");
    //         self.get_random_client_range_key_slot(public_key, index)
    //     } else {
    //         None
    //     }
    // }

    pub fn get_random_control_sum(&self) -> U512 {
        self.random_control_sum.clone()
    }

    pub fn set_random_control_sum(&mut self, random_control_sum: U512) {
        self.random_control_sum = random_control_sum
    }

    // слоты сервера (контролёра)
    pub fn set_random_control_slot(&mut self, public_key: Point, slot: Slot) {
        self.random_control_slots.insert(public_key.x, slot);
    }

    pub fn get_random_control_slot(&self, public_key: Point) -> Option<&Slot> {
        self.random_control_slots.get(&public_key.x)
    }

    pub fn get_random_control_self_value(&self) -> Option<U512> {
        if self.random_control_values.len() > 0 {
            Some(self.random_control_values[self.random_control_values.len()-1].clone())
        } else {
            None
        }
    }

    // main-слоты владельца суммы без прибавления
    pub fn set_main_client_slot(&mut self, public_key: Point, slot: Slot) {
        self.main_client_slots.insert(public_key.x, slot);
    }

    pub fn get_main_client_slot(&self, public_key: Point) -> Option<&Slot> {
        self.main_client_slots.get(&public_key.x)
    }

    // слоты участников сведения счёта
    pub fn set_client_slot(&mut self, client_public_key: Point, index: usize, slot: Slot) {
        self.client_slots
            .entry(client_public_key.x)
            .or_insert_with(BTreeMap::new)
            .insert(index, slot);
    }

    pub fn get_client_slot(&self, client_public_key: Point, index: usize) -> Option<&Slot> {
        self.client_slots
            .get(&client_public_key.x)
            .and_then(|inner_map| inner_map.get(&index))
    }

    pub fn set_point_matrix(&mut self, client_public_key: Point, point: Point) {
        self.matrix_points.insert(client_public_key.x, point);
    }

    pub fn set_point_list(&mut self, client_public_key: Point, point: Point) {
        self.list_points.insert(client_public_key.x, point);
    }

    pub fn set_point_range_verification_key(&mut self, client_public_key: Point, point: Point) {
        self.range_verification_key_points.insert(client_public_key.x, point);
    }

    pub fn is_points_loaded(&self, client_count: usize) -> bool {
        let mp_len = self.matrix_points.len();
        let lp_len = self.list_points.len();
        let rp_len = self.range_verification_key_points.len();

        crate::dd(format!("DEBUG: is_points_loaded {} == {}, {}, {}", &client_count, &mp_len, &lp_len, &rp_len), "range");

        (mp_len == client_count) && (lp_len == client_count) && (rp_len == client_count - 1)
    }

    // Методы для работы с доказательствами диапазона
    pub fn set_bit_proof(&mut self, client_public_key: Point, bit_index: usize, bit_prove: BitProve) {
        self.bit_proofs_parts
            .entry(client_public_key.x.clone())
            .or_insert_with(BTreeMap::new)
            .insert(bit_index, bit_prove);
    }

    // Проверка, собраны ли все битпруфы для клиента
    pub fn are_all_bit_proofs_collected(&self, client_public_key: &Point, expected_count: usize) -> bool {
        if let Some(parts) = self.bit_proofs_parts.get(&client_public_key.x) {
            parts.len() == expected_count
        } else {
            false
        }
    }

    // Сбор всех битпруфов в единый вектор
    pub fn collect_bit_proofs(&self, client_public_key_x: &U512, expected_count: usize) -> Option<Vec<BitProve>> {
        if let Some(parts) = self.bit_proofs_parts.get(&client_public_key_x) {
            if parts.len() == expected_count {
                let mut bit_proofs = Vec::with_capacity(expected_count);
                for i in 0..expected_count {
                    if let Some(bit_prove) = parts.get(&i) {
                        bit_proofs.push(bit_prove.clone());
                    } else {
                        return None;
                    }
                }
                // self.bit_proofs.insert(client_public_key_x.clone(), bit_proofs.clone());
                return Some(bit_proofs);
            }
        }
        None
    }

    pub fn get_controller_matrix_point(&self, decrypt_key: &U512) -> Option<Point> {
        crate::dd(format!("DEBUG solution: Начало get_controller_matrix_point"), "solution");
        // 1. Получаем все BTreeMap<usize, Slot> для каждого клиента
        let slots: Vec<BTreeMap<usize, Slot>> = self.client_slots.clone().into_values().collect();
        crate::dd(format!("DEBUG solution: Количество клиентов со слотами: {}", slots.len()), "solution");
        // 2. Преобразуем каждую BTreeMap в Vec<Slot> (упорядоченный по индексам)
        let slots: Vec<Vec<Slot>> = slots.iter().map(|v | v.clone().into_values().collect()).collect();
        // 3. Берем последний слот из каждого вектора
        let slots: Vec<Slot> = slots.iter().map(|v| v[v.len()-1].clone()).collect();
        crate::dd(format!("DEBUG solution: Собрано {} слотов для контроллера", slots.len()), "solution");
        // 4. Расшифровываем каждый слот ключом контролёра
        let controller_values: Vec<U512> = slots.iter().map(|s| s.decrypt(decrypt_key)).collect();
        crate::dd(format!("DEBUG solution: Расшифрованные значения: {:?}", &controller_values), "solution");
        // 5. Суммируем все расшифрованные значения
        let controller_key_value = welsib_u512_sum(controller_values);
        crate::dd(format!("DEBUG solution: Сумма расшифрованных значений: {:?}", &controller_key_value), "solution");
        // 6. Преобразуем в верификационный ключ (точку на кривой)
        let result = welsib_make_verifying_key(&controller_key_value);
        crate::dd(format!("DEBUG solution: Результирующая точка контроллера: {:?}", &result), "solution");
        result
    }

    pub fn get_controller_list_point(&self) -> Option<Point> {
        if let Some(random_control_self_value) = self.get_random_control_self_value() {
            welsib_make_verifying_key(&random_control_self_value)
        } else {
            None
        }
    }

    // pub fn get_solution(&self, secret_key: &U512) -> Option<Option<Certificate>> {
    //     // вычислить matrix Point из слотов предназначенных серверу-контролёру
    //     // просуммировать Point-ы self.matrix_points между собой и с серверным matrix Point-ом контролёра
    //     // вычислить list Point из слотов предназначенных серверу-контролёру
    //     // просуммировать Point-ы self.list_points между собой и с серверным list Point-ом контролёра
    //     // сравить агрегированные matrix Point с list Point-ом и вернуть true если они равны, иначе - false

    //     // TODO: сделать серверый Decode и декодировать слоты клиентов для контролёра в параллельных процессах через Runner (оптимизация)        
    //     let matrix_client_points: Vec<Point> = self.matrix_points.clone().into_values().collect();
    //     let list_client_points: Vec<Point> = self.list_points.clone().into_values().collect();
    //     let matrix_controller_points = if let Some(controller_matrix_point) = self.get_controller_matrix_point(secret_key) {
    //         vec![controller_matrix_point]
    //     } else {
    //         return None;
    //     };
    //     // println!("Solution Matrix Comtroller Point:\n{:#?}", &matrix_controller_points[0]);
    //     let list_controller_points = if let Some(controller_list_point) = self.get_controller_list_point() {
    //         vec![controller_list_point]
    //     } else {
    //         return None;
    //     };

    //     let matrix_points = [matrix_client_points, matrix_controller_points].concat().to_vec();
    //     // println!("Matrix points (from solution):\n{:#?}", &matrix_points);
    //     let list_points = [list_client_points, list_controller_points].concat().to_vec();
    //     if let Some(p1) = welsib_point_sum(matrix_points.clone()) {
    //         if let Some(p2) = welsib_point_sum(list_points.clone()) {
    //             // println!("DEBUG Solution: {}, {}", &p1.x, &p2.x);
    //             if p1 == p2 {
    //                 let agg_point_hash = hash(&p1.to_be_bytes());
    //                 let signature = welsib_sign(&agg_point_hash, secret_key);
    //                 // TODO: Добавить к Certificate доказательства RANGE из 128 бит BitProve для клиентов с частичными значениями
    //                 Some(Some(Certificate {
    //                     matrix_points,
    //                     list_points,
    //                     agg_point: p1,
    //                     agg_point_hash,
    //                     signature,
    //                 }))
    //             } else {
    //                 Some(None)
    //             }
    //         } else {
    //             None
    //         }
    //     } else {
    //         None
    //     }
    // }

    // pub fn get_solution(&self, secret_key: &U512) -> Option<Option<Certificate>> {
    //     crate::dd(format!("DEBUG solution: Начало get_solution"), "solution");
    //     // вычислить matrix Point из слотов предназначенных серверу-контролёру
    //     // просуммировать Point-ы self.matrix_points между собой и с серверным matrix Point-ом контролёра
    //     // вычислить list Point из слотов предназначенных серверу-контролёру
    //     // просуммировать Point-ы self.list_points между собой и с bit proofs поинтами
    //     // сравнить агрегированные matrix Point с list Point-ом и вернуть true если они равны, иначе - false

    //     // TODO: сделать серверный Decode и декодировать слоты клиентов для контролёра в параллельных процессах через Runner (оптимизация)        
    //     let matrix_client_points: Vec<Point> = self.matrix_points.clone().into_values().collect();

    //     // 1. Отладочная информация о matrix_client_points
    //     crate::dd(format!("DEBUG solution: matrix_client_points count = {}", matrix_client_points.len()), "solution");
    //     for (i, point) in matrix_client_points.iter().enumerate() {
    //         crate::dd(format!("DEBUG solution: matrix_client_points[{}] = {:?}", &i, &point.x), "solution");
    //     }
    //     let list_client_points: Vec<Point> = self.list_points.clone().into_values().collect();

    //     // 2. Отладочная информация о list_client_points
    //     crate::dd(format!("DEBUG solution: list_client_points count = {}", list_client_points.len()), "solution");
    //     for (i, point) in list_client_points.iter().enumerate() {
    //         crate::dd(format!("DEBUG solution: list_client_points[{}] = {:?}", &i, &point.x), "solution");
    //     }

    //     // 3. Отладочная информация о bit_proofs
    //     crate::dd(format!("DEBUG solution: bit_proofs_parts keys: {:?}", self.bit_proofs_parts.keys()), "solution");
        
    //     let mut all_bit_proves = BTreeMap::new();
    //     for (client_x_coord, _) in &self.client_slots {
    //         if let Some(bit_proofs) = self.collect_bit_proofs(client_x_coord, 128) {
    //             crate::dd(format!("DEBUG solution: Собраны bit_proofs для клиента {:?}, count = {}", &client_x_coord, bit_proofs.len()), "solution");
    //             all_bit_proves.insert(client_x_coord.clone(), bit_proofs);
    //         }
    //     }

    //     let curve = EllipticCurve::make_curve_welsib();
    //     let mut bit_proof_points = Vec::new();
    //     for (client_x, bit_proofs) in &all_bit_proves {
    //         let point = range_point_from_bit_proofs(&curve, bit_proofs, 128);
    //         crate::dd(format!("DEBUG solution: Точка из bit_proofs для клиента {:?} = {:?}", &client_x, &point.x), "solution");
    //         bit_proof_points.push(point);
    //     }

    //     // 4. Отладочная информация о controller matrix point
    //     let matrix_controller_points = if let Some(controller_matrix_point) = self.get_controller_matrix_point(secret_key) {
    //         crate::dd(format!("DEBUG solution: matrix_controller_point = {:?}", &controller_matrix_point.x), "solution");
    //         vec![controller_matrix_point]
    //     } else {
    //         crate::dd(format!("DEBUG solution: Не удалось получить matrix_controller_point"), "solution");
    //         return None;
    //     };
        
    //     // ===============================================================
    //     // ВАЖНО: В тестовом примере контролёр НЕ имеет отдельной list точки в p2!
    //     // В p2 (списковая часть) включаются:
    //     // - list-точки клиентов (mvx1, mvx2)
    //     // - точка владельца суммы (rvyp) 
    //     // - точки из BitProve (mvx1_vp, mvx2_vp)
    //     // Но НЕ точка контролёра!
    //     //
    //     // Поэтому возможно нужно убрать list_controller_points из list_points
    //     // и вместо этого добавить bit_proof_points
    //     // ===============================================================
        
    //     // let list_controller_points = if let Some(controller_list_point) = self.get_controller_list_point() {
    //     //     vec![controller_list_point]
    //     // } else {
    //     //     return None;
    //     // };

    //     // 5. Формирование matrix_points и list_points
    //     let matrix_points = [matrix_client_points, matrix_controller_points].concat().to_vec();
    //     crate::dd(format!("DEBUG solution: Всего matrix_points = {}", matrix_points.len()), "solution");
        
    //     // ===============================================================
    //     // TODO: Обновить формирование list_points
    //     // Вариант 1: (если оставить старую логику)
    //     // let list_points = [list_client_points, list_controller_points].concat().to_vec();
    //     //
    //     // Вариант 2: (соответствует тестовому примеру)
    //     // Только точки клиентов (включая владельца суммы)
    //     let mut list_points = list_client_points.clone();
    //     crate::dd(format!("DEBUG solution: Всего list_points = {} ({} клиентских + {} bit_proof)", 
    //                  list_points.len(), list_client_points.len(), bit_proof_points.len()), "solution");
    //     // Добавляем точки из BitProve
    //     list_points.extend(bit_proof_points);
    //     // НЕ добавляем list_controller_points!
    //     // ===============================================================
        
    //     // let list_points = [list_client_points, list_controller_points].concat().to_vec();
        
    //     if let Some(p1) = welsib_point_sum(matrix_points.clone()) {
    //         crate::dd(format!("DEBUG solution: p1 = {:?}", &p1.x), "solution");
    //         if let Some(p2) = welsib_point_sum(list_points.clone()) {
    //             crate::dd(format!("DEBUG solution: p2 = {:?}", &p2.x), "solution");
    //             crate::dd(format!("DEBUG solution: p1 == p2: {}", &p1 == &p2), "solution");
    //             crate::dd(format!("Перед созданием сертификата: \n{:?}\n{:?}", &p1, &p2), "range");

    //             // Дополнительная отладка: выведем все точки в p1 и p2
    //             crate::dd(format!("DEBUG solution: Точки в matrix_points:"), "solution");
    //             for (i, point) in matrix_points.iter().enumerate() {
    //                 crate::dd(format!("  [{}] {:?}", &i, &point.x), "solution");
    //             }

    //             crate::dd(format!("DEBUG solution: Точки в list_points:"), "solution");
    //             for (i, point) in list_points.iter().enumerate() {
    //                 crate::dd(format!("  [{}] {:?}", &i, &point.x), "solution");
    //             }

    //             crate::dd(format!("Перед созданием сертификата: \n{:?}\n{:?}", &p1, &p2), "range");

    //             if p1 == p2 {
    //                 let agg_point_hash = hash(&p1.to_be_bytes());
    //                 let signature = welsib_sign(&agg_point_hash, secret_key);
                    
    //                 Some(Some(Certificate {
    //                     matrix_points,
    //                     list_points,
    //                     bit_proves: all_bit_proves,
    //                     agg_point: p1,
    //                     agg_point_hash,
    //                     signature,
    //                 }))
    //             } else {
    //                 crate::dd(format!("DEBUG solution: ОШИБКА: p1 != p2"), "solution");
    //                 Some(None)
    //             }
    //         } else {
    //             crate::dd(format!("DEBUG solution: Не удалось вычислить p2"), "solution");
    //             None
    //         }
    //     } else {
    //         crate::dd(format!("DEBUG solution: Не удалось вычислить p1"), "solution");
    //         None
    //     }
    // }

    /// Добавляет клиентскую h-точку (публичный ключ) в список для последующей верификации
    /// 
    /// # Аргументы
    /// - `h`: ссылка на точку (публичный ключ) клиента
    pub fn insert_client_h(&mut self, h: &Point) {
        self.client_h_list.push(h.clone());
    }

    /// Возвращает список всех клиентских h-точек (публичных ключей)
    /// 
    /// # Возвращает
    /// Вектор клиентских точек для вычисления агрегированного ключа
    pub fn get_client_h_list(&self) -> Vec<Point> {
        self.client_h_list.clone()
    }

    pub fn get_solution(&self, secret_key: &U512) -> Option<Option<Certificate>> {
        crate::dd(format!("DEBUG cmp: =================================================="), "cmp");
        crate::dd(format!("DEBUG cmp: ЗНАЧЕНИЯ ИЗ СЕТЕВОГО КОДА:"), "cmp");
        crate::dd(format!("DEBUG cmp: =================================================="), "cmp");

        // ===============================================================
        // 0. ПРОВЕРКА КЛЮЧЕЙ (дополнительная верификация)
        // ===============================================================
        // Проверка использования оригинальных ключей на основе ключа контролёра
        if let Some(h_main) = self.get_h_main() {
            // Получаем список всех клиентских h-точек
            let client_h_list = self.get_client_h_list();
            crate::dd(format!("DEBUG cmp: Количество клиентских h-точек: {}", client_h_list.len()), "cmp");
            
            // Вычисляем агрегированную точку
            let curve = EllipticCurve::make_curve_welsib();
            if let Some(h_agg) = curve.point_sum(client_h_list) {
                crate::dd(format!("DEBUG cmp: h_main = 0x{:016x}", h_main.x.get()[0]), "cmp");
                crate::dd(format!("DEBUG cmp: h_agg = 0x{:016x}", h_agg.x.get()[0]), "cmp");

                if h_main != h_agg {
                    crate::dd(format!("DEBUG cmp: ВНИМАНИЕ: h_main != h_agg! Проверка ключей не пройдена!"), "cmp");
                    // В реальном коде здесь может быть возврат ошибки или другая обработка
                    return Some(None);
                } else {
                    crate::dd(format!("DEBUG cmp: Проверка ключей пройдена успешно"), "cmp");
                }
            }
        }
        
        // ===============================================================
        // 1. MATRIX POINTS (клиентские точки для p1)
        // ===============================================================
        let matrix_client_points: Vec<Point> = self.matrix_points.clone().into_values().collect();
        
        crate::dd(format!("DEBUG cmp: matrix_client_points count = {}", matrix_client_points.len()), "cmp");
        for (i, point) in matrix_client_points.iter().enumerate() {
            crate::dd(format!("DEBUG cmp:   matrix_client_points[{}] = 0x{:016x}", i, point.x.get()[0]), "cmp");
        }
        
        // ===============================================================
        // 2. LIST POINTS (клиентские точки для p2)
        // ===============================================================
        let list_client_points: Vec<Point> = self.list_points.clone().into_values().collect();
        
        crate::dd(format!("DEBUG cmp: list_client_points count = {}", list_client_points.len()), "cmp");
        for (i, point) in list_client_points.iter().enumerate() {
            crate::dd(format!("DEBUG cmp:   list_client_points[{}] = 0x{:016x}", i, point.x.get()[0]), "cmp");
        }
        
        // ===============================================================
        // 3. BIT PROOFS (доказательства диапазона)
        // ===============================================================
        let client_keys: Vec<String> = self.bit_proofs_parts.keys()
            .map(|k| format!("0x{:016x}", k.get()[0]))
            .collect();
        crate::dd(format!("DEBUG cmp: bit_proofs_parts клиенты: {:?}", client_keys), "cmp");
        
        let mut all_bit_proves = BTreeMap::new();
        let mut bit_proof_points = Vec::new();
        
        for (client_x_coord, _) in &self.client_slots {
            if let Some(bit_proofs) = self.collect_bit_proofs(client_x_coord, 128) {
                crate::dd(format!("DEBUG cmp:   Собраны bit_proofs для клиента 0x{:016x}, count = {}", 
                    client_x_coord.get()[0], bit_proofs.len()), "cmp_bp");

                // Выводим информацию о каждом BitProve (новая структура)
                for (i, bit_prove) in bit_proofs.iter().enumerate() {
                    let debug_line = format!(
                        "bit_proofs2[{}]: t.x = 0x{:016x}, r1 = 0x{:016x}, r2 = 0x{:016x}, diff.x = 0x{:016x}, c.x = 0x{:016x}, z.x = 0x{:016x}",
                        i,
                        bit_prove.t.x.get()[0],
                        bit_prove.r1.get()[0],
                        bit_prove.r2.get()[0],
                        bit_prove.diff.x.get()[0],
                        bit_prove.c.x.get()[0],
                        bit_prove.z.x.get()[0]
                    );
                    crate::dd(format!("DEBUG cmp_bp: {}", debug_line), "cmp_bp");
                }
                
                all_bit_proves.insert(client_x_coord.clone(), bit_proofs.clone());
                
                // Преобразуем BitProve в точку
                let curve = EllipticCurve::make_curve_welsib();
                let point = range_point_from_bit_proofs(&curve, &bit_proofs, 128);
                crate::dd(format!("DEBUG cmp:   Точка из bit_proofs для клиента 0x{:016x} = 0x{:016x}", 
                    client_x_coord.get()[0], point.x.get()[0]), "cmp");
                bit_proof_points.push(point);
            }
        }
        
        // ===============================================================
        // 4. CONTROLLER MATRIX POINT (точка контролёра для p1)
        // ===============================================================
        let matrix_controller_points = if let Some(controller_matrix_point) = self.get_controller_matrix_point(secret_key) {
            crate::dd(format!("DEBUG cmp: controller_matrix_point (mc) = 0x{:016x}", 
                controller_matrix_point.x.get()[0]), "cmp");
            vec![controller_matrix_point]
        } else {
            crate::dd(format!("DEBUG cmp: ОШИБКА: Не удалось получить controller_matrix_point"), "cmp");
            return None;
        };
        
        // ===============================================================
        // 5. СБОРКА ВСЕХ ТОЧЕК ДЛЯ P1 И P2
        // ===============================================================
        let matrix_points = [matrix_client_points, matrix_controller_points].concat().to_vec();
        crate::dd(format!("DEBUG cmp: Всего matrix_points для p1 = {}", matrix_points.len()), "cmp");
        
        // ВАЖНО: list_points должны содержать ТОЛЬКО точки клиентов и bit_proof_points
        let mut list_points = list_client_points.clone();
        crate::dd(format!("DEBUG cmp: list_points (клиенты) = {}, bit_proof_points = {}", 
            list_points.len(), bit_proof_points.len()), "cmp");
        
        // Добавляем точки из BitProve
        list_points.extend(bit_proof_points);
        crate::dd(format!("DEBUG cmp: Всего list_points для p2 = {}", list_points.len()), "cmp");
        
        // ===============================================================
        // 6. ВЫЧИСЛЕНИЕ И СРАВНЕНИЕ P1 И P2
        // ===============================================================
        if let Some(p1) = welsib_point_sum(matrix_points.clone()) {
            crate::dd(format!("DEBUG cmp: p1 (матрица) = 0x{:016x}", p1.x.get()[0]), "cmp");
            
            if let Some(p2) = welsib_point_sum(list_points.clone()) {
                crate::dd(format!("DEBUG cmp: p2 (список) = 0x{:016x}", p2.x.get()[0]), "cmp");
                
                crate::dd(format!("DEBUG cmp: =================================================="), "cmp");
                crate::dd(format!("DEBUG cmp: ИТОГОВОЕ СРАВНЕНИЕ:"), "cmp");
                crate::dd(format!("DEBUG cmp:   p1 == p2: {}", p1 == p2), "cmp");
                crate::dd(format!("DEBUG cmp:   p1.x[0] = 0x{:016x}", p1.x.get()[0]), "cmp");
                crate::dd(format!("DEBUG cmp:   p2.x[0] = 0x{:016x}", p2.x.get()[0]), "cmp");
                crate::dd(format!("DEBUG cmp: =================================================="), "cmp");
                
                // Дополнительная отладка: выведем все точки в p1 и p2
                crate::dd(format!("DEBUG cmp: Точки в matrix_points (для p1):"), "cmp");
                for (i, point) in matrix_points.iter().enumerate() {
                    let point_type = if i < matrix_points.len() - 1 { "клиент" } else { "контролёр" };
                    crate::dd(format!("DEBUG cmp:   [{}] {}: 0x{:016x}", i, point_type, point.x.get()[0]), "cmp");
                }

                crate::dd(format!("DEBUG cmp: Точки в list_points (для p2):"), "cmp");
                for (i, point) in list_points.iter().enumerate() {
                    let point_type = if i < list_client_points.len() { "клиент list" } else { "bit_proof" };
                    crate::dd(format!("DEBUG cmp:   [{}] {}: 0x{:016x}", i, point_type, point.x.get()[0]), "cmp");
                }
                
                crate::dd(format!("DEBUG cmp: =================================================="), "cmp");

                if p1 == p2 {
                    // let agg_point_hash = hash(&p1.to_be_bytes());
                    let mut ph_hash = p1.to_be_bytes();
                    if let Some(h_main) = self.get_h_main() {
                        ph_hash.extend(h_main.to_be_bytes());
                    }
                    let agg_point_hash = hash(&ph_hash);
                    let signature = welsib_sign(&agg_point_hash, secret_key);

                    Some(Some(Certificate {
                        h_main: self.get_h_main(),
                        client_h_list: self.get_client_h_list(),
                        matrix_points,
                        list_points,
                        bit_proves: all_bit_proves,
                        agg_point: p1,
                        agg_point_hash,
                        signature, // TODO: в зависимости от p1 и h_main
                    }))
                } else {
                    crate::dd(format!("DEBUG cmp: ОШИБКА: p1 != p2"), "cmp");
                    crate::dd(format!("DEBUG cmp:   p1.x[0] = 0x{:016x}", p1.x.get()[0]), "cmp");
                    crate::dd(format!("DEBUG cmp:   p2.x[0] = 0x{:016x}", p2.x.get()[0]), "cmp");
                    crate::dd(format!("DEBUG cmp:   p1.y[0] = 0x{:016x}", p1.y.get()[0]), "cmp");
                    crate::dd(format!("DEBUG cmp:   p2.y[0] = 0x{:016x}", p2.y.get()[0]), "cmp");
                    
                    Some(None)
                }
            } else {
                crate::dd(format!("DEBUG cmp: ОШИБКА: Не удалось вычислить p2"), "cmp");
                None
            }
        } else {
            crate::dd(format!("DEBUG cmp: ОШИБКА: Не удалось вычислить p1"), "cmp");
            None
        }
    }
}
