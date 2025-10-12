// use crate::smpc::WelsibDtoInterface;
use std::collections::HashMap;
use welsib_json::{JsonValue, from_json, to_json};

#[derive(Debug)]
pub struct HandshakeRequestAttributes {}

impl HandshakeRequestAttributes {
    pub fn to_json(&self) -> String {
        let json_obj = JsonValue::Object(HashMap::new());
        to_json(&json_obj)
    }
}

// impl WelsibDtoInterface for HandshakeRequestAttributes {}