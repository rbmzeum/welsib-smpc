use crate::base64::safe_encode;
use crate::smpc::response::ResponseStatus;
// use crate::smpc::WelsibDtoInterface;
use welsib_u512_ec::sign::Signature;
use welsib_json::{JsonValue, from_json, to_json};
use std::collections::HashMap;

#[derive(Debug)]
pub struct SendSlotResponseAttributes {
    status: String,
    signature: String
}

impl SendSlotResponseAttributes {
    pub fn new(status: ResponseStatus, signature: &Signature) -> Self {
        Self {
            status: String::from(match status {
                ResponseStatus::Success => "success",
                ResponseStatus::Failed => "failed",
                _ => "undefined"
            }),
            signature: safe_encode(&signature.to_be_bytes())
        }
    }

    pub fn from_json(json: &str) -> Option<Self> {
        let json = json.to_string().replace("\\\"", "\"");
        if let JsonValue::Object(obj) = from_json(json.as_str()).unwrap() {
            let status = if let Some(JsonValue::String(status)) = obj.get("status") {
                status.clone()
            } else {
                return None;
            };

            let signature = if let Some(JsonValue::String(signature)) = obj.get("signature") {
                signature.clone()
            } else {
                return None;
            };

            Some(Self {
                status,
                signature
            })
        } else {
            None
        }
    }

    pub fn is_success(&self, signature: &String) -> bool {
        self.status == String::from("success") && self.signature == *signature
    }

    pub fn to_json(&self) -> String {
        let mut obj = HashMap::new();
        obj.insert(String::from("status"), JsonValue::String(self.status.clone()));
        obj.insert(String::from("signature"), JsonValue::String(self.signature.clone()));
        let json_obj = JsonValue::Object(obj);
        to_json(&json_obj)
    }
}

// impl WelsibDtoInterface for SendSlotResponseAttributes {}