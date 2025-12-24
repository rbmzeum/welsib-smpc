use crate::{base64::safe_encode, helpers::arg_key::Keypair};
use crate::smpc::slot::{Slot, SlotType};
// use crate::smpc::WelsibDtoInterface;
use welsib_json::{JsonValue, from_json, to_json};
use welsib_u512_ec::sign::welsib_sign;
use crate::hash::hash;
use std::collections::HashMap;

#[derive(Debug)]
pub struct SendPointRequestAttributes {
    pub point_bytes: Vec<u8>,
    pub client_index: usize, // индекс для извлечения из конфига публичного ключа клиента config[client_index]
    // pub bit_index: Option<usize>,
    pub nonce_sig: String, // nonce_sig = sign(hash(current_time_in_milliseconds div 8000), app_secret_key)
    pub signature: String, // сигнатура клиента
}

impl SendPointRequestAttributes {
    pub fn new(point_bytes: Vec<u8>, client_index: usize, nonce_sig: String, keypair: &Keypair) -> Self {
        let client_index_bytes = client_index.to_be_bytes().to_vec();
        let bytes = [
            nonce_sig.as_bytes().to_vec(),
            point_bytes.clone(),
            client_index_bytes,
        ].concat();
        let attr_hash = hash(&bytes);
        // println!("Attributes Hash: {:?}", &attr_hash);
        // println!("Attributes Key: {:?}", &keypair.get_public_key());
        let signature = welsib_sign(&attr_hash, &keypair.get_secret_key());
        // println!("Attribute Signature: {:?}", &signature);
        let signature_str = safe_encode(&signature.to_be_bytes());

        Self {
            point_bytes,
            client_index,
            nonce_sig,
            signature: signature_str,
        }
    }

    pub fn from_json(json: &str) -> Option<Self> {
        let json = json.to_string().replace("\\\"", "\"");
        if let JsonValue::Object(obj) = from_json(json.as_str()).unwrap() {
            let point_bytes = if let Some(JsonValue::Array(point_bytes)) = obj.get("point_bytes") {
                point_bytes.iter().map(|j_val| if let JsonValue::Number(v) = j_val { v.clone() as u8 } else { 0 /* NB! */ } ).collect::<Vec<u8>>()
            } else {
                return None;
            };

            let client_index = if let Some(JsonValue::Number(client_index)) = obj.get("client_index") {
                client_index.clone() as usize // NB! mantissa
            } else {
                return None;
            };

            let nonce_sig = if let Some(JsonValue::String(nonce_sig)) = obj.get("nonce_sig") {
                nonce_sig.clone()
            } else {
                return None;
            };

            let signature = if let Some(JsonValue::String(signature)) = obj.get("signature") {
                signature.clone()
            } else {
                return None;
            };

            Some(Self {
                point_bytes,
                client_index,
                nonce_sig,
                signature,
            })
        } else {
            None
        }
    }

    pub fn to_json(&self) -> String {
        let mut obj = HashMap::new();
        obj.insert(String::from("point_bytes"), JsonValue::Array(self.point_bytes.clone().iter().map(|v| { JsonValue::Number(v.clone() as u64) }).collect::<Vec<_>>()));
        obj.insert(String::from("client_index"), JsonValue::Number(self.client_index.clone() as u64));
        obj.insert(String::from("nonce_sig"), JsonValue::String(self.nonce_sig.clone()));
        obj.insert(String::from("signature"), JsonValue::String(self.signature.clone()));
        let json_obj = JsonValue::Object(obj);
        to_json(&json_obj)
    }
}

// impl WelsibDtoInterface for SendPointRequestAttributes {}