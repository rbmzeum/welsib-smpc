pub mod encode;
pub mod decode;
pub mod aggregate;

use crate::server::smpc_field::SMPCField;
use std::sync::{Arc, Mutex};

pub trait Calculation: Send + Sync {
    fn new(field: Arc<Mutex<SMPCField>>) -> Self where Self: Sized;
    fn calculation(&self);
}