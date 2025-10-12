use crate::{base64::safe_encode, helpers::arg_key::Keypair};
use crate::smpc::slot::{Slot, SlotType};
// use crate::smpc::WelsibDtoInterface;
use welsib_json::{JsonValue, from_json, to_json};
use welsib_u512_ec::sign::welsib_sign;
use crate::hash::hash;
use std::collections::HashMap;

#[derive(Debug)]
pub struct ReceiveSlotRequestAttributes {
    pub slot_type: SlotType, // Тип слота: контролёрский, целая сумма, части
    pub slot_index: usize, // индекс для извлечения слотов (строка в матрице ixj)
    pub client_index: usize, // индекс для извлечения из конфига публичного ключа клиента config[client_index] (столбец в матрице ixj)
    pub nonce_sig: String, // nonce_sig = sign(hash(current_time_in_milliseconds div 8000), app_secret_key)
    pub signature: String, // сигнатура клиента
}

impl ReceiveSlotRequestAttributes {
    pub fn new(slot_type: SlotType, slot_index: usize, client_index: usize, nonce_sig: String, keypair: &Keypair) -> Self {
        let slot_type_byte = match slot_type { SlotType::Controller => 1u8, SlotType::Main => 2, SlotType::Value => 3, _ => 0};
        let slot_index_bytes = slot_index.to_be_bytes().to_vec();
        let client_index_bytes = client_index.to_be_bytes().to_vec();
        let bytes = [
            nonce_sig.as_bytes().to_vec(),
            vec![slot_type_byte],
            slot_index_bytes,
            client_index_bytes,
        ].concat();
        let attr_hash = hash(&bytes);
        // println!("Attributes Hash: {:?}", &attr_hash);
        // println!("Attributes Key: {:?}", &keypair.get_public_key());
        let signature = welsib_sign(&attr_hash, &keypair.get_secret_key());
        // println!("Attribute Signature: {:?}", &signature);
        let signature_str = safe_encode(&signature.to_be_bytes());

        Self {
            slot_type,
            slot_index,
            client_index,
            nonce_sig,
            signature: signature_str,
        }
    }

    pub fn from_json(json: &str) -> Option<Self> {
        let json = json.to_string().replace("\\\"", "\"");
        if let JsonValue::Object(obj) = from_json(json.as_str()).unwrap() {
            let slot_type = if let Some(JsonValue::String(slot_type)) = obj.get("slot_type") {
                match slot_type.as_str() {
                    "Controller" => SlotType::Controller,
                    "Main" => SlotType::Main,
                    "Value" => SlotType::Value,
                    _ => { return None; }
                }
            } else {
                return None;
            };

            let slot_index = if let Some(JsonValue::Number(slot_index)) = obj.get("slot_index") {
                slot_index.clone() as usize // NB! mantissa
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
                slot_type,
                slot_index,
                client_index,
                nonce_sig,
                signature
            })
        } else {
            None
        }
    }

    pub fn to_json(&self) -> String {
        let mut obj = HashMap::new();
        obj.insert(String::from("slot_type"), JsonValue::String(String::from(match self.slot_type {
            SlotType::Controller => "Controller", SlotType::Main => "Main", SlotType::Value => "Value"
        })));
        obj.insert(String::from("slot_index"), JsonValue::Number(self.slot_index.clone() as u64));
        obj.insert(String::from("client_index"), JsonValue::Number(self.client_index.clone() as u64));
        obj.insert(String::from("nonce_sig"), JsonValue::String(self.nonce_sig.clone()));
        obj.insert(String::from("signature"), JsonValue::String(self.signature.clone()));
        let json_obj = JsonValue::Object(obj);
        to_json(&json_obj)
    }
}

// impl WelsibDtoInterface for ReceiveSlotRequestAttributes {}