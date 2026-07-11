use crate::conv::u2vec::u2vec;
use crate::conv::vec2u::vec2u;
use welsib_u512::u512::U512;
use welsib_u512_ec::point::Point;
use welsib_u512_ec::agg_crypt::welsib_agg_encrypt;
use welsib_u512_ec::agg_crypt::welsib_agg_decrypt;

#[derive(Debug, Clone)]
pub enum SlotType {
    Controller, // слоты сервера (контролёра, проверяющего, аудитора)
    Main, // слоты клиента без добаления конфиденциального значения к случайным частям
    Value, // слоты клиента с добавленным значением
    Key, // слоты для совместимости с range proof
    // Bit
}

#[derive(Debug, Clone)]
pub struct Slot {
    bytes: Vec<u8>,
}

impl Slot {
    pub fn encrypt(value: &U512, encrypt_key: &Point) -> Self {
        // println!("Encrypt slot: {}", &value);
        Self {
            bytes: welsib_agg_encrypt(&u2vec(value.clone()), encrypt_key)
        }
    }

    pub fn decrypt(&self, decrypt_key: &U512) -> U512 {
        // println!("Decrypt slot len: {}", &self.bytes.len());
        crate::dd(format!("DEBUG: (Slot::decrypt inner):\n{:x?}\n", &decrypt_key.get()[0]), "keypair");
        vec2u(welsib_agg_decrypt(&self.bytes, decrypt_key))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes
        }
    }
}
