use crate::client::Calculation;
use std::sync::{Arc, Mutex};
use welsib_u512::u512::U512;
use welsib_u512_ec::point::Point;
use crate::client::SMPCBuffer;
use crate::smpc::slot::{Slot, SlotType};

pub struct Encode {
    smpc_buffer: Arc<Mutex<SMPCBuffer>>,
    slot_type: Option<SlotType>,
    value: Option<U512>,
    public_key: Option<Point>,
}

impl Calculation for Encode {
    fn new(smpc_buffer: Arc<Mutex<SMPCBuffer>>) -> Self {
        Self {
            smpc_buffer,
            slot_type: None,
            value: None,
            public_key: None,
        }
    }

    // fn set_value(&self, value: U512)
    // fn set_public_key(&self, public_key: Point)
    // fn set_secret_key(&self, secret_key: U512)
    // fn set_slot(&self, slot: Slot)

    fn calculation(&self) {
        // println!("Performing encoding calculations...");
        if let Some(value) = &self.value {
            if let Some(public_key) = &self.public_key {
                let slot = Slot::encrypt(value, public_key);
                if let Ok(mut smpc_buffer) = self.smpc_buffer.lock() {
                    // println!("Set slot for:\n{:?}\n{:?}", &public_key, &slot);
                    // В зависимости от типа слота записывать в соответствующие переменные
                    if let Some(slot_type) = &self.slot_type {
                        match *slot_type {
                            SlotType::Controller => {
                                // Сюда клиент не попадает
                            },
                            SlotType::Main => {
                                // println!("DEBUG calculation completed (Main)");
                                smpc_buffer.insert_random_nonce_slot(public_key.clone(), slot);
                            },
                            SlotType::Value => {
                                // println!("DEBUG calculation completed (Value)");
                                smpc_buffer.insert_client_slot(public_key.clone(), slot);
                            },
                            SlotType::Key => {
                                smpc_buffer.insert_range_slot(public_key.clone(), slot);
                            }
                        }
                    }
                }
            }
        }
        // println!("Completed encoding calculations.");
    }
}

impl Encode {
    pub fn set_slot_type(&mut self, slot_type: SlotType) {
        self.slot_type = Some(slot_type)
    }

    pub fn set_value(&mut self, value: U512) {
        self.value = Some(value)
    }

    pub fn set_public_key(&mut self, public_key: Point) {
        self.public_key = Some(public_key)
    }
}