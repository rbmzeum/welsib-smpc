use crate::base64::safe_encode;
use std::time::{SystemTime, UNIX_EPOCH};
// use crate::smpc::WelsibDtoInterface;
use welsib_json::{JsonValue, from_json, to_json};
use welsib_u512_ec::sign::welsib_sign;
use crate::hash::hash;
use welsib_u512::u512::U512;
use std::collections::HashMap;

#[derive(Debug)]
pub struct HandshakeResponseAttributes {
    pub nonce_sig: String,  // nonce_sig = sign(hash(current_time_in_milliseconds div 8000), app_secret_key)
}

impl HandshakeResponseAttributes {
    pub fn new(private_key: &U512) -> Self {
        // FIXME: unwrap_or_default потенциально не безопасный код
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() / 8000; // div 8 seconds
        // println!("HandshakeResponseAttributes (now): {}", &now);
        let hash = hash(&(now).to_be_bytes().to_vec());
        let nonce_sig = safe_encode(&welsib_sign(&hash, &private_key).to_be_bytes());
        Self {
            nonce_sig
        }
    }

    pub fn from_json(json: &str) -> Option<Self> {
        let json = json.to_string().replace("\\\"", "\"");
        if let JsonValue::Object(obj) = from_json(json.as_str()).unwrap() {
            let nonce_sig = if let Some(JsonValue::String(nonce_sig)) = obj.get("nonce_sig") {
                nonce_sig.clone()
            } else {
                return None;
            };

            Some(Self {
                nonce_sig
            })
        } else {
            None
        }
    }

    pub fn to_json(&self) -> String {
        let mut obj = HashMap::new();
        obj.insert(String::from("nonce_sig"), JsonValue::String(self.nonce_sig.clone()));
        let json_obj = JsonValue::Object(obj);
        to_json(&json_obj)
    }
}

// impl WelsibDtoInterface for HandshakeResponseAttributes {}