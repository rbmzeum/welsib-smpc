// Secure Multi-Party Computation (SMPC)
pub mod slot;
pub mod request;
pub mod response;
pub mod point_type;

use crate::checksum::crc32;
// use serde::Serialize;

// pub trait WelsibDtoInterface
// where
//     Self: Serialize,
// {
//     fn to_json<T>(&self) -> String
//     where
//         T: ?Sized + Serialize,
//     {
//         match serde_json::to_string(self) {
//             Ok(json) => json,
//             Err(_e) => String::new(),
//         }
//     }

//     // TODO: выяснить как правильно сделать этот метод в трейте
//     // fn from_json<T>(json: &str) -> Option<T>
//     // where
//     //     T: ?Sized + Serialize,
//     // {
//     //     match serde_json::from_str::<T>(json) {
//     //         Ok(response) => {
//     //             Some(response)
//     //         }
//     //         _ => None,
//     //     }
//     // }

//     fn to_frame<T>(&self) -> Vec<u8>
//     where
//         T: ?Sized + Serialize,
//         Self: Serialize,
//     {
//         let json = self.to_json::<T>();
//         let cs = crc32(&(json.len() as u32).to_be_bytes().to_vec());
//         let mut bytes: Vec<u8> = [(json.len() as u32).to_be_bytes(), cs.to_be_bytes()].concat();
//         bytes.append(&mut json.as_bytes().to_vec());
//         bytes
//     }
// }