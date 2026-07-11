// use crate::certificate::Certificate;
// use crate::helpers::arg_conf::Config;
// use crate::helpers::pipe_certificate::StdInCertificate;
// use welsib_u512_ec::sign::welsib_point_sum;
// use welsib_u512_ec::verify::welsib_verify;
// use welsib_u512_ec::hash::whash;
// use welsib_u512_ec::point::Point;
// use welsib_u512::u512::U512;
// use welsib_u512_ec::elliptic_curve::EllipticCurve;
// use crate::range_prove::{range_verify, range_point_from_bit_proofs, BitProvePublicKey};

// pub mod print_help;
// pub mod arguments;

// pub struct Verifier {
//     certificate: Certificate,
//     verify_key: Point,
//     public_keys: Vec<Point>,  // Все публичные ключи из конфига
// }

// impl Verifier {
//     pub fn new(config: &Config, stdin_certificate: &StdInCertificate) -> std::io::Result<Self> {
//         let public_keys = config.get_public_keys().clone();
//         let verify_key = if let Some(verify_key) = public_keys.last() {
//             verify_key.clone()
//         } else {
//             return Err(std::io::Error::new(
//                 std::io::ErrorKind::InvalidInput,
//                 "Некорректный формат конфигурационного файла",
//             ));
//         };

//         let certificate = Certificate::from_lines(&stdin_certificate.lines)?;

//         Ok(Self {
//             certificate,
//             verify_key,
//             public_keys,
//         })
//     }

//     // pub fn run(&mut self) -> std::io::Result<(bool, bool, bool, bool)> {
//     //     // 1. Проверить matrix_point_agg == agg_point
//     //     let matrix_point_agg = if let Some(matrix_point_agg) = welsib_point_sum(self.certificate.matrix_points.clone()) { matrix_point_agg } else {
//     //         return Err(std::io::Error::new(
//     //             std::io::ErrorKind::InvalidInput,
//     //             "Некорретный формат certificate.matrix_points",
//     //         ));
//     //     };
//     //     let is_verified_matrix_agg_points = self.certificate.agg_point == matrix_point_agg;
//     //     // 2. Проверить list_point_agg == agg_point
//     //     let list_point_agg = if let Some(list_point_agg) = welsib_point_sum(self.certificate.list_points.clone()) { list_point_agg } else {
//     //         return Err(std::io::Error::new(
//     //             std::io::ErrorKind::InvalidInput,
//     //             "Некорретный формат certificate.list_points",
//     //         ));
//     //     };
//     //     let is_verified_list_agg_points = self.certificate.agg_point == list_point_agg;
//     //     // 3. Проверить hash(agg_point) == agg_point_hash
//     //     let is_verified_agg_point_hash = U512::from_be_bytes(&whash(&self.certificate.agg_point.to_be_bytes())) == self.certificate.agg_point_hash;
//     //     // 4. verify(agg_point_hash, signature, verifier_key)
//     //     let is_verified_signature = welsib_verify(&self.certificate.agg_point_hash, &self.certificate.signature, &self.verify_key);

//     //     Ok((is_verified_matrix_agg_points, is_verified_list_agg_points, is_verified_agg_point_hash, is_verified_signature))
//     // }

//     pub fn run(&mut self) -> std::io::Result<(bool, bool, bool, bool, bool)> {
//         // 1. Проверить matrix_point_agg == agg_point
//         let matrix_point_agg = if let Some(matrix_point_agg) = welsib_point_sum(self.certificate.matrix_points.clone()) {
//             matrix_point_agg
//         } else {
//             return Err(std::io::Error::new(
//                 std::io::ErrorKind::InvalidInput,
//                 "Некорректный формат certificate.matrix_points",
//             ));
//         };
//         let is_verified_matrix_agg_points = self.certificate.agg_point == matrix_point_agg;
        
//         // 2. Проверить list_point_agg == agg_point
//         let list_point_agg = if let Some(list_point_agg) = welsib_point_sum(self.certificate.list_points.clone()) {
//             list_point_agg
//         } else {
//             return Err(std::io::Error::new(
//                 std::io::ErrorKind::InvalidInput,
//                 "Некорректный формат certificate.list_points",
//             ));
//         };
//         let is_verified_list_agg_points = self.certificate.agg_point == list_point_agg;
        
//         // 3. Проверить все range proofs (bit_proves)
//         let mut is_verified_bit_proves = true;
//         let curve = EllipticCurve::make_curve_welsib();
        
//         for (client_x_coord, bit_proofs) in &self.certificate.bit_proves {
//             // Найти публичный ключ клиента
//             let client_pub_key = self.public_keys.iter()
//                 .find(|p| p.x == *client_x_coord);
            
//             if let Some(client_pub_key) = client_pub_key {
//                 // Найти соответствующую точку в list_points
//                 let list_point = self.certificate.list_points.iter()
//                     .find(|p| p.x == *client_x_coord);
                
//                 if let Some(list_point) = list_point {
//                     // Проверить range proof
//                     let range = 128; // Как в тестовом примере
//                     let bp_verify_key = BitProvePublicKey::new(client_pub_key.clone());
                    
//                     if !range_verify(&curve, bit_proofs, range, bp_verify_key.get_h(), list_point.clone()) {
//                         is_verified_bit_proves = false;
//                         break;
//                     }
//                 } else {
//                     is_verified_bit_proves = false;
//                     break;
//                 }
//             } else {
//                 is_verified_bit_proves = false;
//                 break;
//             }
//         }
        
//         // 4. Проверить hash(agg_point) == agg_point_hash
//         let is_verified_agg_point_hash = U512::from_be_bytes(&whash(&self.certificate.agg_point.to_be_bytes())) 
//             == self.certificate.agg_point_hash;
        
//         // 5. verify(agg_point_hash, signature, verifier_key)
//         let is_verified_signature = welsib_verify(
//             &self.certificate.agg_point_hash,
//             &self.certificate.signature,
//             &self.verify_key
//         );

//         Ok((
//             is_verified_matrix_agg_points,
//             is_verified_list_agg_points,
//             is_verified_bit_proves,
//             is_verified_agg_point_hash,
//             is_verified_signature
//         ))
//     }
// }

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


use crate::certificate::Certificate;
use crate::helpers::arg_conf::Config;
use crate::helpers::pipe_certificate::StdInCertificate;
use welsib_u512_ec::sign::welsib_point_sum;
use welsib_u512_ec::verify::welsib_verify;
use welsib_u512_ec::hash::whash;
use welsib_u512_ec::point::Point;
use welsib_u512::u512::U512;
use welsib_u512_ec::elliptic_curve::EllipticCurve;
use crate::range_prove::{range_verify, range_point_from_bit_proofs, BitProvePublicKey};
use welsib_u512_ec::sign::EllipticCurveSign;

pub mod print_help;
pub mod arguments;

pub struct Verifier {
    pub certificate: Certificate,
    verify_key: Point,
    pub public_keys: Vec<Point>,  // Все публичные ключи из конфига
}

impl Verifier {
    pub fn new(config: &Config, stdin_certificate: &StdInCertificate) -> std::io::Result<Self> {
        let public_keys = config.get_public_keys().clone();
        let verify_key = if let Some(verify_key) = public_keys.last() {
            verify_key.clone()
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Некорректный формат конфигурационного файла",
            ));
        };

        let certificate = Certificate::from_lines(&stdin_certificate.lines)?;

        Ok(Self {
            certificate,
            verify_key,
            public_keys,
        })
    }

    pub fn run(&mut self) -> std::io::Result<(
        bool, // is_verified_matrix_agg_points
        bool, // is_verified_list_agg_points
        bool, // is_verified_bit_proves
        bool, // is_verified_agg_point_hash
        bool, // is_verified_signature
        bool, // is_verified_h_keys
        bool, // is_verified_all_range_proofs
        bool, // is_verified_p1_eq_p2
        bool, // is_verified_agg_point_match
    )> {
        // Создание кривой для проверок
        let curve = EllipticCurve::make_curve_welsib();
        const RANGE: usize = 128;
        
        // 1. Проверить matrix_point_agg == agg_point
        let matrix_point_agg = if let Some(matrix_point_agg) = welsib_point_sum(self.certificate.matrix_points.clone()) {
            matrix_point_agg
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Некорректный формат certificate.matrix_points",
            ));
        };
        let is_verified_matrix_agg_points = self.certificate.agg_point == matrix_point_agg;
        
        // 2. Проверить list_point_agg == agg_point (только list_points без bit_proves)
        let list_point_agg = if let Some(list_point_agg) = welsib_point_sum(self.certificate.list_points.clone()) {
            list_point_agg
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Некорректный формат certificate.list_points",
            ));
        };
        let is_verified_list_agg_points = self.certificate.agg_point == list_point_agg;
        
        // 3. Проверить все range proofs (bit_proves)
        let mut is_verified_bit_proves = true;
        let mut client_count = 0;
        
        for (client_x_coord, bit_proofs) in &self.certificate.bit_proves {
            client_count += 1;
            
            // Найти публичный ключ клиента
            let client_pub_key = self.public_keys.iter()
                .find(|p| p.x == *client_x_coord);
            
            if let Some(client_pub_key) = client_pub_key {
                // Найти соответствующую точку в list_points
                let list_point = self.certificate.list_points.iter()
                    .find(|p| p.x == *client_x_coord);
                
                if let Some(list_point) = list_point {
                    // Проверить range proof
                    let bp_verify_key = BitProvePublicKey::new(client_pub_key.clone());
                    
                    if !range_verify(&curve, bit_proofs, RANGE, bp_verify_key.get_h(), list_point.clone()) {
                        is_verified_bit_proves = false;
                        break;
                    }
                } else {
                    is_verified_bit_proves = false;
                    break;
                }
            } else {
                is_verified_bit_proves = false;
                break;
            }
        }
        
        // 4. Проверить hash(agg_point) == agg_point_hash
        let is_verified_agg_point_hash = U512::from_be_bytes(&whash(&self.certificate.agg_point.to_be_bytes())) 
            == self.certificate.agg_point_hash;
        
        // 5. verify(agg_point_hash, signature, verifier_key)
        let is_verified_signature = welsib_verify(
            &self.certificate.agg_point_hash,
            &self.certificate.signature,
            &self.verify_key
        );
        
        // =========================================================================
        // ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ ИЗ ТЕСТОВОГО КОДА
        // =========================================================================
        
        // 6. Проверка ключей верификации доказательств диапазонов
        let mut is_verified_h_keys = false;
        if let Some(h_main) = &self.certificate.h_main {
            // Суммируем все клиентские h-точки
            if let Some(h_agg) = welsib_point_sum(self.certificate.client_h_list.clone()) {
                is_verified_h_keys = h_main == &h_agg;
            }
        }
        
        // 7. Расширенная проверка доказательств диапазонов для каждого клиента
        let mut is_verified_all_range_proofs = true;
        let mut range_client_count = 0;
        
        for (client_x_coord, bit_proofs) in &self.certificate.bit_proves {
            range_client_count += 1;
            
            // Находим соответствующий публичный ключ клиента
            let client_pub_key = self.public_keys.iter()
                .find(|p| p.x == *client_x_coord);
            
            if let Some(client_pub_key) = client_pub_key {
                // Находим соответствующую точку в list_points
                let list_point = self.certificate.list_points.iter()
                    .find(|p| p.x == *client_x_coord);
                
                if let Some(list_point) = list_point {
                    // Проверяем range proof
                    if !range_verify(&curve, bit_proofs, RANGE, client_pub_key, list_point.clone()) {
                        is_verified_all_range_proofs = false;
                        break;
                    }
                    
                    // Дополнительная проверка: сравниваем точки из bit_proofs с confidential_value
                    let range_point = range_point_from_bit_proofs(&curve, bit_proofs, RANGE);
                    if &range_point != list_point {
                        is_verified_all_range_proofs = false;
                        break;
                    }
                } else {
                    is_verified_all_range_proofs = false;
                    break;
                }
            } else {
                is_verified_all_range_proofs = false;
                break;
            }
        }
        
        // 8. Итоговая верификация: сравнение p1 и p2
        let p1 = if let Some(p1_point) = welsib_point_sum(self.certificate.matrix_points.clone()) {
            p1_point
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Не удалось вычислить p1 (матрица)",
            ));
        };
        
        // Собираем все точки для p2: list_points + точки из bit_proves
        let mut p2_points = self.certificate.list_points.clone();
        for (client_x_coord, bit_proofs) in &self.certificate.bit_proves {
            let point_from_bit_proofs = range_point_from_bit_proofs(&curve, bit_proofs, RANGE);
            p2_points.push(point_from_bit_proofs);
        }
        
        let p2 = if let Some(p2_point) = welsib_point_sum(p2_points) {
            p2_point
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Не удалось вычислить p2 (список + bit_proves)",
            ));
        };
        
        let is_verified_p1_eq_p2 = p1 == p2;
        
        // 9. Сравниваем с agg_point из сертификата
        let is_verified_agg_point_match = p1 == self.certificate.agg_point && p2 == self.certificate.agg_point;

        Ok((
            is_verified_matrix_agg_points,
            is_verified_list_agg_points,
            is_verified_bit_proves,
            is_verified_agg_point_hash,
            is_verified_signature,
            is_verified_h_keys,
            is_verified_all_range_proofs,
            is_verified_p1_eq_p2,
            is_verified_agg_point_match,
        ))
    }
}