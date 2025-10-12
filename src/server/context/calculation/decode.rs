use crate::server::Calculation;
use std::thread::sleep;
use std::sync::{Arc, Mutex};
use crate::server::smpc_field::SMPCField;
// use crate::smpc::slot::Slot;

pub struct Decode {
    smpc_field: Arc<Mutex<SMPCField>>,
}

impl Calculation for Decode {
    fn new(smpc_field: Arc<Mutex<SMPCField>>) -> Self {
        Self { smpc_field }
    }

    fn calculation(&self) {
        // println!("Performing decoding calculations...");
        sleep(std::time::Duration::from_secs(5));
        // println!("Completed decoding calculations.");
    }
}