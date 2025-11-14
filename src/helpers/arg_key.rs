use crate::conv::u2vec::u2vec;
use std::{fs, path::PathBuf, str::FromStr};
use crate::conv::vec2u::vec2u;
use crate::hash::hash;
use welsib_u512_ec::point::Point;
use welsib_tools::tools::base64::{base64_encode, base64_decode};
use welsib_u512_ec::hash::whash;
use welsib_u512::u512::{U512, U1024, U1024Rem};
use welsib_u512_ec::elliptic_curve::EllipticCurve;
use welsib_u512_ec::agg_crypt::EllipticCurveCrypt;
use welsib_u512_ec::keys::{make_signing_key, make_verifying_key};

#[derive(Debug, Clone)]
pub struct Keypair {
    secret_key: U512,
    public_key: Point
}

impl Keypair {
    pub fn encode(filename: String, password: String) -> std::io::Result<Self> {
        let password_hash = whash(&password.as_bytes());
        let curve = EllipticCurve::make_curve_welsib();

        if let Some(password_key) = U1024::new_from_u512(&U512::from_be_bytes(&password_hash)) % &curve.q {
            let key_path = PathBuf::from(filename);
            let key_file_contents = std::fs::read_to_string(key_path)?;
            let mut base64_encrypted_key = String::new();
            for line in key_file_contents.lines() {
                if let Some(p) = line.find("-----") {
                    continue;
                }
                base64_encrypted_key += line.trim();
            }

            if base64_encrypted_key.len() ==  0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Неизвестный формат PEM файла ключа"
                ));
            }

            let encrypted_key = base64_decode(&base64_encrypted_key);
            // println!("Encrypted key: {:?}", &encrypted_key);
            let decrypted_key = curve.agg_decrypt(&encrypted_key, &password_key);
            // println!("Decrypted key: {:?}", &decrypted_key);
            if decrypted_key.len() == 64 {
                let key = U512::from_be_bytes(&decrypted_key.try_into().unwrap());
                // println!("Key: {:?}", &key);
                let point = if let Some(point) = make_verifying_key(&curve, &key) {
                    point
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Ошибка создания публичного ключа"
                    ));
                };

                Ok(Self {
                    secret_key: key,
                    public_key: point
                })
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Неправильный размер ключа"
                ));
            }
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Ошибка создания хеша пароля"
            ));
        }
    }

    // pub fn encode(filename: String, gamma: &Vec<u8>, key: &Vec<u8>) -> std::io::Result<Self> {
    //     let keyfile_data = Self::extract_file(filename, gamma, key)?;
    //     let key_bytes = Self::validate_keyfile_data(&keyfile_data)?;
    //     let secret_key = vec2u(key_bytes);
    //     let public_key = if let Some(public_key) = make_verifying_key(&secret_key) {
    //         public_key
    //     } else {
    //         return Err(std::io::Error::new(
    //             std::io::ErrorKind::InvalidData,
    //             "Не удалось создать публичный ключ.",
    //         ));
    //     };

    //     Ok(Self {
    //         secret_key,
    //         public_key
    //     })
    // }

    // fn extract_file(filename: String, gamma: &Vec<u8>, key: &Vec<u8>) -> std::io::Result<Vec<u8>> {
    //     if filename.is_empty() {
    //         return Err(std::io::Error::new(
    //             std::io::ErrorKind::InvalidFilename,
    //             "Имя файла не может быть пустым",
    //         ));
    //     }

    //     let path = PathBuf::from(filename);

    //     if !fs::exists(&path)? {
    //         return Err(std::io::Error::new(
    //             std::io::ErrorKind::NotFound,
    //             format!("Файл {:?} не найден", path),
    //         ));
    //     }

    //     // Формула генерации: encrypt([root_key_bytes, hash(root_key_bytes)].concat(), gamma, key)
    //     let encrypted_data = fs::read(path)?;
    //     // println!("Encrypted: {:#?}", &encrypted_data.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    //     // println!("Encrypted len: {:#?}", encrypted_data.len());

    //     if encrypted_data.len() != 128 {
    //         return Err(std::io::Error::new(
    //             std::io::ErrorKind::InvalidData,
    //             "Размер файла не соответствует ожидаемому",
    //         ));
    //     }

    //     let key_bytes: [u8; 32] = key.clone().try_into().unwrap();
    //     let data = esig::crypt::decrypt(encrypted_data, &gamma, &key_bytes);

    //     Ok(data)
    // }

    // fn validate_keyfile_data(data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
    //     // println!("Decrypted: {:#?}", &data.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    //     // println!("Decrypted len: {:#?}", data.len());
    //     let key_bytes = data[0..64].to_vec();
    //     let hash_key = hash(&key_bytes);
    //     let hash_key_bytes = data[64..128].to_vec();
    //     // println!("Hash: {:#?}", bigint2vec(hash_key.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>());
    //     // println!("Hash2: {:#?}", hash_key_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    //     if bigint2vec(hash_key) != hash_key_bytes {
    //         return Err(std::io::Error::new(
    //             std::io::ErrorKind::InvalidData,
    //             "Контрольная хешсумма не совпадает с вычисленной, следовательно данные - не достоверны",
    //         ));
    //     }

    //     Ok(key_bytes)
    // }

    // fn make_hash_for_file(filename: String) -> std::io::Result<BigInt> {
    //     // TODO: считывать файл по частям, если файл большого размера
    //     let bytes = std::fs::read(&filename)?;
    //     let hash = hash(&bytes);
    //     Ok(hash)
    // }

    pub fn get_secret_key(&self) -> U512 {
        self.secret_key.clone()
    }

    pub fn get_public_key(&self) -> Point {
        self.public_key.clone()
    }

}
