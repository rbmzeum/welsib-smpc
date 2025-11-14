use crate::client::Calculation;
use std::thread::sleep;
use std::sync::{Arc, Mutex};
use crate::client::SMPCBuffer;
use crate::smpc::slot::Slot;
use welsib_u512::u512::U512;

pub struct DecodeKey {
    smpc_buffer: Arc<Mutex<SMPCBuffer>>,
    slot: Option<Slot>,
    slot_position: Option<usize>,
    decode_key: Option<U512>,
}

impl Calculation for DecodeKey {
    fn new(smpc_buffer: Arc<Mutex<SMPCBuffer>>) -> Self {
        Self {
            smpc_buffer,
            slot: None,
            slot_position: None,
            decode_key: None,
        }
    }

    fn calculation(&self) {
        // println!("Performing decoding calculations...");
        // sleep(std::time::Duration::from_secs(5));
        crate::dd(format!("Performing decoding calculations..."), "agg_received_key");
        if let Some(slot) = &self.slot {
            crate::dd(format!("DEBUG: (slot)"), "agg_received_key");
            if let Some(decode_key) = &self.decode_key {
                crate::dd(format!("DEBUG: (decode_key)"), "agg_received_key");
                if let Some(slot_position) = self.slot_position {
                    crate::dd(format!("DEBUG: (slot_position)"), "agg_received_key");
                    crate::dd(format!("DEBUG: (Slot::decrypt):\n{:x?}\n{:x?}\n", &slot_position, &decode_key.get()[0]), "keypair");
                    let key = Slot::decrypt(slot, decode_key);
                    crate::dd(format!("DEBUG: (Slot::decrypt, after):\n{:x?}\n", &key.get()[0]), "keypair");
                    loop {
                        if let Ok(mut smpc_buffer) = self.smpc_buffer.lock() {
                            // println!("Set decoded value: \n{:?}", &value);
                            crate::dd(format!("DEBUG: (key)"), "agg_received_key");
                            // Записать в smpc_buffer результат декодирования слота в соответствующую позицию
                            smpc_buffer.insert_received_key(slot_position, key);
                            break;
                        } else {
                            crate::dd(format!("DEBUG: (key, smpc_buffer, locked). Try again..."), "agg_received_key");
                            sleep(std::time::Duration::from_millis(10));
                        }
                    }
                } else {
                    // println!("DEBUG Decoding: (self.slot_position is None)");
                    crate::dd(format!("DEBUG: (slot_position is None)"), "agg_received_key");
                }
            } else {
                // println!("DEBUG Decoding: (self.decode_key is None)");
                crate::dd(format!("DEBUG: (decode_key is None)"), "agg_received_key");
            }
        } else {
            // println!("DEBUG Decoding: (self.slot is None)");
            crate::dd(format!("DEBUG: (slot is None)"), "agg_received_key");
        }
        // println!("Completed decoding calculations.");
        crate::dd(format!("DEBUG: Completed decoding calculations."), "agg_received_key");
    }
}

impl DecodeKey {
    pub fn set_slot(&mut self, slot: Slot) {
        self.slot = Some(slot)
    }

    pub fn set_slot_position(&mut self, slot_position: usize) {
        self.slot_position = Some(slot_position)
    }
    
    pub fn set_decode_key(&mut self, decode_key: U512) {
        self.decode_key = Some(decode_key)
    }
}