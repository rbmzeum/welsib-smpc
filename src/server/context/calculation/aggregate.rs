use crate::server::Calculation;
use std::thread::sleep;
use std::sync::{Arc, Mutex};
use crate::server::smpc_field::SMPCField;
// use crate::smpc::slot::Slot;

pub struct Aggregate {
    smpc_field: Arc<Mutex<SMPCField>>,
}

impl Calculation for Aggregate {
    fn new(smpc_field: Arc<Mutex<SMPCField>>) -> Self {
        Self { smpc_field }
    }

    fn calculation(&self) {
        // println!("Performing aggregate calculations...");
        sleep(std::time::Duration::from_secs(1));
        // println!("Completed aggregate calculations.");
    }
}