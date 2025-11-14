pub mod encode;
pub mod decode;
pub mod decode_key;
pub mod aggregate;

use crate::client::SMPCBuffer;
use std::sync::{Arc, Mutex};

pub trait Calculation: Send + Sync {
    fn new(field: Arc<Mutex<SMPCBuffer>>) -> Self where Self: Sized;
    fn calculation(&self);
}