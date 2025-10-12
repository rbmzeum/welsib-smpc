use crate::client::Calculation;
use std::thread::sleep;
use std::sync::{Arc, Mutex};
use crate::client::SMPCBuffer;
use crate::smpc::slot::Slot;
use welsib_u512::u512::U512;

pub struct Decode {
    smpc_buffer: Arc<Mutex<SMPCBuffer>>,
    slot: Option<Slot>,
    slot_position: Option<usize>,
    decode_key: Option<U512>,
}

impl Calculation for Decode {
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
        if let Some(slot) = &self.slot {
            if let Some(decode_key) = &self.decode_key {
                if let Some(slot_position) = self.slot_position {
                    let value = Slot::decrypt(slot, decode_key);
                    if let Ok(mut smpc_buffer) = self.smpc_buffer.lock() {
                        // println!("Set decoded value: \n{:?}", &value);
                        // Записать в smpc_buffer результат декодирования слота в соответствующую позицию
                        smpc_buffer.insert_received_value(slot_position, value);
                    }
                } else {
                    // println!("DEBUG Decoding: (self.slot_position is None)");
                }
            } else {
                // println!("DEBUG Decoding: (self.decode_key is None)");
            }
        } else {
            // println!("DEBUG Decoding: (self.slot is None)");
        }
        // println!("Completed decoding calculations.");
    }
}

impl Decode {
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