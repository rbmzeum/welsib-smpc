use crate::client::Calculation;
use std::thread::sleep;
use std::sync::{Arc, Mutex};
use crate::client::SMPCBuffer;
// use crate::smpc::slot::Slot;

pub struct Aggregate {
    smpc_field: Arc<Mutex<SMPCBuffer>>,
}

impl Calculation for Aggregate {
    fn new(smpc_field: Arc<Mutex<SMPCBuffer>>) -> Self {
        Self { smpc_field }
    }

    fn calculation(&self) {
        // println!("Performing aggregate calculations...");
        sleep(std::time::Duration::from_secs(1));
        // println!("Completed aggregate calculations.");
    }
}