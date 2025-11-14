use crate::certificate::Certificate;
use crate::smpc::slot::{Slot, SlotType};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::helpers::shifted_random::create_shifted_random;
use crate::server::context::calculation::encode::Encode;
use crate::random::create_random_additive_parts;
use crate::server::context::calculation::Calculation;
use crate::helpers::arg_key::Keypair;
use crate::hash::hash;
use welsib_u512_ec::sign::welsib_sign;
use welsib_u512_ec::sign::welsib_point_sum;
use welsib_u512_ec::keys::welsib_make_verifying_key;
use welsib_u512_ec::point::Point;
use welsib_u512::u512::U512;
use welsib_u512_ec::sign::welsib_u512_sum;

#[derive(Debug)]
pub struct SMPCField {
    // ключи range proof (server)
    random_control_range_key: U512,
    random_control_range_key_parts: Option<Vec<U512>>,
    random_client_range_key_slots: BTreeMap<U512, BTreeMap<usize, Slot>>,

    // TODO: range bit proof (128 points от каждого клиента)

    // серверные ключи контролёра
    random_control_sum: U512,
    random_control_values: Vec<U512>,
    random_control_slots: BTreeMap<U512, Slot>, // key: Point.x, value: Slot
    // ключи клиентов
    client_slots: BTreeMap<U512, BTreeMap<usize, Slot>>,
    main_client_slots: BTreeMap<U512, Slot>,
    matrix_points: BTreeMap<U512, Point>,
    list_points: BTreeMap<U512, Point>,
    // TODO: range random value points
}

impl SMPCField {
    pub fn new() -> Self {
        let random_control_sum = create_shifted_random(); // устанавливается из результата range proof
        let random_control_range_key = create_shifted_random();
        Self {
            random_control_range_key,
            random_control_range_key_parts: None,
            random_client_range_key_slots: BTreeMap::new(),
            //
            random_control_sum,
            random_control_values: vec![],
            random_control_slots: BTreeMap::new(),
            client_slots: BTreeMap::new(),
            main_client_slots: BTreeMap::new(),
            matrix_points: BTreeMap::new(),
            list_points: BTreeMap::new(),
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
    // END DEBUG

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

    pub fn is_points_loaded(&self, client_count: usize) -> bool {
        let mp_len = self.matrix_points.len();
        let lp_len = self.list_points.len();

        (mp_len == client_count) && (lp_len == client_count)
    }

    pub fn get_controller_matrix_point(&self, decrypt_key: &U512) -> Option<Point> {
        let slots: Vec<BTreeMap<usize, Slot>> = self.client_slots.clone().into_values().collect();
        let slots: Vec<Vec<Slot>> = slots.iter().map(|v | v.clone().into_values().collect()).collect();
        let slots: Vec<Slot> = slots.iter().map(|v| v[v.len()-1].clone()).collect(); // TODO: учесть, что длина v может быть равна нулю, тогда функция вернёт None
        let controller_values: Vec<U512> = slots.iter().map(|s| s.decrypt(decrypt_key)).collect();
        let controller_key_value = welsib_u512_sum(controller_values);
        welsib_make_verifying_key(&controller_key_value)
    }

    pub fn get_controller_list_point(&self) -> Option<Point> {
        if let Some(random_control_self_value) = self.get_random_control_self_value() {
            welsib_make_verifying_key(&random_control_self_value)
        } else {
            None
        }
    }

    pub fn get_solution(&self, secret_key: &U512) -> Option<Option<Certificate>> {
        // вычислить matrix Point из слотов предназначенных серверу-контролёру
        // просуммировать Point-ы self.matrix_points между собой и с серверным matrix Point-ом контролёра
        // вычислить list Point из слотов предназначенных серверу-контролёру
        // просуммировать Point-ы self.list_points между собой и с серверным list Point-ом контролёра
        // сравить агрегированные matrix Point с list Point-ом и вернуть true если они равны, иначе - false

        // TODO: сделать серверый Decode и декодировать слоты клиентов для контролёра в параллельных процессах через Runner (оптимизация)        
        let matrix_client_points: Vec<Point> = self.matrix_points.clone().into_values().collect();
        let list_client_points: Vec<Point> = self.list_points.clone().into_values().collect();
        let matrix_controller_points = if let Some(controller_matrix_point) = self.get_controller_matrix_point(secret_key) {
            vec![controller_matrix_point]
        } else {
            return None;
        };
        // println!("Solution Matrix Comtroller Point:\n{:#?}", &matrix_controller_points[0]);
        let list_controller_points = if let Some(controller_list_point) = self.get_controller_list_point() {
            vec![controller_list_point]
        } else {
            return None;
        };

        let matrix_points = [matrix_client_points, matrix_controller_points].concat().to_vec();
        // println!("Matrix points (from solution):\n{:#?}", &matrix_points);
        let list_points = [list_client_points, list_controller_points].concat().to_vec();
        if let Some(p1) = welsib_point_sum(matrix_points.clone()) {
            if let Some(p2) = welsib_point_sum(list_points.clone()) {
                // println!("DEBUG Solution: {}, {}", &p1.x, &p2.x);
                if p1 == p2 {
                    let agg_point_hash = hash(&p1.to_be_bytes());
                    let signature = welsib_sign(&agg_point_hash, secret_key);
                    Some(Some(Certificate {
                        matrix_points,
                        list_points,
                        agg_point: p1,
                        agg_point_hash,
                        signature,
                    }))
                } else {
                    Some(None)
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}
