use crate::{base64::safe_encode, helpers::arg_key::Keypair};
// use crate::smpc::request::SMPCRequestAttributes;
use welsib_json::{JsonValue, from_json, to_json};
use welsib_u512_ec::sign::welsib_sign;
use crate::hash::hash;
use crate::base64;
use std::collections::HashMap;

#[derive(Debug)]
pub struct SendBitProofRequestAttributes {
    pub bit_proof_base64: String,
    pub bit_index: usize, // индекс бита в доказательстве диапазона (0..127)
    pub client_index: usize, // индекс клиента в конфигурации
    pub nonce_sig: String, // nonce_sig = sign(hash(current_time_in_milliseconds div 8000), app_secret_key)
    pub signature: String, // сигнатура клиента
}

impl SendBitProofRequestAttributes {
    pub fn new(
        bit_proof_frame: Vec<u8>, 
        bit_index: usize, 
        client_index: usize, 
        nonce_sig: String, 
        keypair: &Keypair
    ) -> Self {
        // Конвертируем в base64
        let bit_proof_base64 = safe_encode(&bit_proof_frame);

        // Конвертируем индексы в байтовые представления
        let bit_index_bytes = bit_index.to_be_bytes().to_vec();
        let client_index_bytes = client_index.to_be_bytes().to_vec();
        
        // Создаем данные для подписи: nonce_sig + bit_proof_frame + bit_index + client_index
        let bytes = [
            nonce_sig.as_bytes().to_vec(),
            bit_proof_frame.clone(),
            bit_index_bytes,
            client_index_bytes,
        ].concat();
        
        // Хэшируем данные и создаем подпись
        let attr_hash = hash(&bytes);
        let signature = welsib_sign(&attr_hash, &keypair.get_secret_key());
        let signature_str = safe_encode(&signature.to_be_bytes());

        Self {
            bit_proof_base64,
            bit_index,
            client_index,
            nonce_sig,
            signature: signature_str,
        }
    }

    pub fn from_json(json: &str) -> Option<Self> {
        let json = json.to_string().replace("\\\"", "\"");
        if let Ok(JsonValue::Object(obj)) = from_json(json.as_str()) {
            let bit_proof_base64 = if let Some(JsonValue::String(bit_proof_base64)) = obj.get("bit_proof_base64") {
                bit_proof_base64.clone()
            } else {
                return None;
            };

            // Извлекаем bit_index
            let bit_index = if let Some(JsonValue::Number(bit_index)) = obj.get("bit_index") {
                *bit_index as usize
            } else {
                return None;
            };

            // Извлекаем client_index
            let client_index = if let Some(JsonValue::Number(client_index)) = obj.get("client_index") {
                *client_index as usize
            } else {
                return None;
            };

            // Извлекаем nonce_sig
            let nonce_sig = if let Some(JsonValue::String(nonce_sig)) = obj.get("nonce_sig") {
                nonce_sig.clone()
            } else {
                return None;
            };

            // Извлекаем signature
            let signature = if let Some(JsonValue::String(signature)) = obj.get("signature") {
                signature.clone()
            } else {
                return None;
            };

            Some(Self {
                bit_proof_base64,
                bit_index,
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
        
        obj.insert(
            String::from("bit_proof_base64"), 
            JsonValue::String(self.bit_proof_base64.clone())
        );
        
        obj.insert(
            String::from("bit_index"), 
            JsonValue::Number(self.bit_index as u64)
        );
        
        obj.insert(
            String::from("client_index"), 
            JsonValue::Number(self.client_index as u64)
        );
        
        obj.insert(
            String::from("nonce_sig"), 
            JsonValue::String(self.nonce_sig.clone())
        );
        
        obj.insert(
            String::from("signature"), 
            JsonValue::String(self.signature.clone())
        );
        
        let json_obj = JsonValue::Object(obj);
        to_json(&json_obj)
    }
}

// impl SMPCRequestAttributes for SendBitProofRequestAttributes {
//     fn get_signature(&self) -> Vec<u8> {
//         // Декодируем base64 подпись обратно в байты
//         match base64::safe_decode(&self.signature) {
//             Ok(bytes) => bytes,
//             Err(_) => Vec::new(),
//         }
//     }
// }