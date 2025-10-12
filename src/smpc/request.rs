pub mod handshake;
pub mod send_slot;
pub mod send_point;
pub mod receive_slot;

use crate::checksum::crc32;
// use crate::smpc::WelsibDtoInterface;
use welsib_json::{JsonValue, from_json, to_json};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SMPCRequest {
    command: String,    // command
    attributes: String, // json
}

impl SMPCRequest {
    pub fn new(command: String, attributes: String) -> Self {
        Self {
            command,
            attributes: attributes.replace("\"", "\\\"").replace("\\\\\"", "\\\"")
        }
    }

    pub fn from_json(json: &str) -> Option<Self> {
        if let JsonValue::Object(obj) = from_json(json).unwrap() {
            let command = if let Some(JsonValue::String(command)) = obj.get("command") {
                command.clone()
            } else {
                return None;
            };

            let attributes = if let Some(JsonValue::String(attributes)) = obj.get("attributes") {
                attributes.clone().replace("\"", "\\\"").replace("\\\\\"", "\\\"")
            } else {
                return None;
            };

            Some(Self {
                command,
                attributes
            })
        } else {
            None
        }
    }

    pub fn from_frame(frame: &Vec<u8>) -> Option<Self> {
        // аутентификация
        let header_size: [u8; 4] = frame[0..4].try_into().unwrap_or_default();
        let cs = crc32(&header_size.to_vec());
        let checksum: [u8; 4] = frame[4..8].try_into().unwrap_or_default();
        if u32::from_be_bytes(checksum) != cs {
            // контрольная сумма не верна
            None
        } else {
            // контрольная сумма верна
            let json_bytes = frame[8..].to_vec();
            let mut json = String::from_utf8(json_bytes).unwrap_or("".to_string());
            json.truncate(u32::from_be_bytes(header_size) as usize);
            Self::from_json(json.as_str())
        }
    }

    pub fn to_frame(&self) -> Vec<u8> {
        let mut obj = HashMap::new();
        obj.insert(String::from("command"), JsonValue::String(self.command.clone()));
        obj.insert(String::from("attributes"), JsonValue::String(self.attributes.clone()));
        let json_obj = JsonValue::Object(obj);
        let json = to_json(&json_obj);
        let cs = crc32(&(json.len() as u32).to_be_bytes().to_vec());
        let mut bytes: Vec<u8> = [(json.len() as u32).to_be_bytes(), cs.to_be_bytes()].concat();
        bytes.append(&mut json.as_bytes().to_vec());
        bytes
    }

    pub fn command(&self) -> String {
        self.command.clone()
    }

    pub fn attributes(&self)  -> String {
        self.attributes.clone()
    }
}

// impl WelsibDtoInterface for SMPCRequest {}
