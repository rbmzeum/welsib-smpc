// use welsib_smpc::helpers::arg_conf::Config;
// use welsib_smpc::verifier::print_help::print_help;
// use welsib_smpc::verifier::arguments::WelsibVerifierArguments;
// use welsib_smpc::helpers::pipe_certificate::StdInCertificate;
// use welsib_smpc::verifier::Verifier;

// // Верификация сертификата созданного SMPC сервером
// fn main() -> std::io::Result<()> {
//     // Init
//     let arguments = WelsibVerifierArguments::init();
//     if arguments.need_help() {
//         print_help();
//         return Ok(());
//     }
//     // println!("Arguments: {:#?}", &arguments);

//     let stdin_certificate = StdInCertificate::read()?;
//     // println!("Certificate: {:#?}", &stdin_certificate);

//     let config = Config::read(arguments.get_config_filename()?)?;
//     // println!("Config: {:#?}", &config);

//     // Run
//     let mut verifier = Verifier::new(&config, &stdin_certificate)?;
//     let is_verified = verifier.run()?;

//     // Done
//     // if let (is_verified_matrix_agg_points, is_verified_list_agg_points, is_verified_agg_point_hash, is_verified_signature) = is_verified {
//     //     println!("matrix_points_agg == agg_point: {}", if is_verified_matrix_agg_points {"true"} else {"false"});
//     //     println!("list_points_agg == agg_point: {}", if is_verified_list_agg_points {"true"} else {"false"});
//     //     println!("hash(agg_point) == agg_point_hash: {}", if is_verified_agg_point_hash {"true"} else {"false"});
//     //     println!("signature verified: {}", if is_verified_signature {"true"} else {"false"});
//     // }

//     // Вывод результатов
//     if let (is_verified_matrix_agg_points, is_verified_list_agg_points, 
//             is_verified_bit_proves, is_verified_agg_point_hash, 
//             is_verified_signature) = is_verified {
//         println!("matrix_points_agg == agg_point: {}", 
//                  if is_verified_matrix_agg_points {"true"} else {"false"});
//         println!("list_points_agg + bit_proves_agg == agg_point: {}", 
//                  if is_verified_list_agg_points {"true"} else {"false"});
//         println!("bit_proves верифицированы (Range Proof): {}", 
//                  if is_verified_bit_proves {"true"} else {"false"});
//         println!("hash(agg_point) == agg_point_hash: {}", 
//                  if is_verified_agg_point_hash {"true"} else {"false"});
//         println!("signature verified: {}", 
//                  if is_verified_signature {"true"} else {"false"});
//     }

//     Ok(())
// }

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

// use welsib_smpc::helpers::arg_conf::Config;
// use welsib_smpc::verifier::print_help::print_help;
// use welsib_smpc::verifier::arguments::WelsibVerifierArguments;
// use welsib_smpc::helpers::pipe_certificate::StdInCertificate;
// use welsib_smpc::verifier::Verifier;
// use welsib_u512_ec::elliptic_curve::EllipticCurve;
// use welsib_smpc::range_prove::{range_verify, range_point_from_bit_proofs};

// // Верификация сертификата созданного SMPC сервером
// fn main() -> std::io::Result<()> {
//     // Init
//     let arguments = WelsibVerifierArguments::init();
//     if arguments.need_help() {
//         print_help();
//         return Ok(());
//     }
    
//     let stdin_certificate = StdInCertificate::read()?;
//     let config = Config::read(arguments.get_config_filename()?)?;
    
//     // Создание кривой для проверок
//     let curve = EllipticCurve::make_curve_welsib();
//     const RANGE: usize = 128; // Как в тестовом коде

//     // Run
//     let mut verifier = Verifier::new(&config, &stdin_certificate)?;
//     let is_verified = verifier.run()?;

//     // =========================================================================
//     // ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ ИЗ ТЕСТОВОГО КОДА
//     // =========================================================================

//     // 1. Проверка ключей верификации доказательств диапазонов
//     if let Some(h_main) = &verifier.certificate.h_main {
//         // Суммируем все клиентские h-точки
//         if let Some(h_agg) = curve.point_sum(verifier.certificate.client_h_list.clone()) {
//             if h_main != &h_agg {
//                 println!("WARNING: Проверка ключей верификации не пройдена!");
//                 println!("  h_main != h_agg");
//                 println!("  h_main.x[0] = 0x{:016x}", h_main.x.get()[0]);
//                 println!("  h_agg.x[0] = 0x{:016x}", h_agg.x.get()[0]);
//             } else {
//                 println!("Проверка ключей верификации: УСПЕХ");
//             }
//         }
//     }
    
//     // 2. Проверка доказательств диапазонов для каждого клиента
//     let mut all_range_proofs_verified = true;
//     let mut client_count = 0;
    
//     for (client_x_coord, bit_proofs) in &verifier.certificate.bit_proves {
//         client_count += 1;
        
//         // Находим соответствующий публичный ключ клиента
//         let client_pub_key = verifier.public_keys.iter()
//             .find(|p| p.x == *client_x_coord);
        
//         if let Some(client_pub_key) = client_pub_key {
//             // Находим соответствующую точку в list_points
//             let list_point = verifier.certificate.list_points.iter()
//                 .find(|p| p.x == *client_x_coord);
            
//             if let Some(list_point) = list_point {
//                 // Проверяем range proof
//                 if !range_verify(&curve, bit_proofs, RANGE, client_pub_key, list_point.clone()) {
//                     println!("WARNING: Range proof верификация не пройдена для клиента 0x{:016x}", 
//                              client_x_coord.get()[0]);
//                     all_range_proofs_verified = false;
//                 } else {
//                     // Дополнительная проверка: сравниваем точки из bit_proofs с confidential_value
//                     let range_point = range_point_from_bit_proofs(&curve, bit_proofs, RANGE);
//                     if &range_point != list_point {
//                         println!("WARNING: Точка из bit_proofs не совпадает с confidential_value для клиента 0x{:016x}", 
//                                  client_x_coord.get()[0]);
//                         all_range_proofs_verified = false;
//                     }
//                 }
//             } else {
//                 println!("WARNING: Не найдена точка в list_points для клиента 0x{:016x}", 
//                          client_x_coord.get()[0]);
//                 all_range_proofs_verified = false;
//             }
//         } else {
//             println!("WARNING: Не найден публичный ключ для клиента 0x{:016x}", 
//                      client_x_coord.get()[0]);
//             all_range_proofs_verified = false;
//         }
//     }
    
//     if all_range_proofs_verified && client_count > 0 {
//         println!("Проверка всех range proofs: УСПЕХ ({} клиентов)", client_count);
//     } else if client_count == 0 {
//         println!("WARNING: В сертификате отсутствуют доказательства диапазонов");
//     }
    
//     // 3. Итоговая верификация: сравнение p1 и p2
//     let p1 = if let Some(matrix_point_agg) = welsib_u512_ec::sign::welsib_point_sum(verifier.certificate.matrix_points.clone()) {
//         matrix_point_agg
//     } else {
//         println!("ERROR: Не удалось вычислить p1 (матрица)");
//         return Ok(());
//     };
    
//     // Собираем все точки для p2: list_points + точки из bit_proves
//     let mut p2_points = verifier.certificate.list_points.clone();
//     for (client_x_coord, bit_proofs) in &verifier.certificate.bit_proves {
//         let point_from_bit_proofs = range_point_from_bit_proofs(&curve, bit_proofs, RANGE);
//         p2_points.push(point_from_bit_proofs);
//     }
    
//     let p2 = if let Some(list_point_agg) = welsib_u512_ec::sign::welsib_point_sum(p2_points) {
//         list_point_agg
//     } else {
//         println!("ERROR: Не удалось вычислить p2 (список + bit_proves)");
//         return Ok(());
//     };
    
//     // Сравниваем p1 и p2
//     if p1 == p2 {
//         println!("Итоговая проверка p1 == p2: УСПЕХ");
//         println!("  p1.x[0] = 0x{:016x}", p1.x.get()[0]);
//         println!("  p2.x[0] = 0x{:016x}", p2.x.get()[0]);
//     } else {
//         println!("ERROR: Итоговая проверка p1 == p2 НЕ ПРОЙДЕНА!");
//         println!("  p1.x[0] = 0x{:016x}", p1.x.get()[0]);
//         println!("  p2.x[0] = 0x{:016x}", p2.x.get()[0]);
//     }
    
//     // 4. Сравниваем с agg_point из сертификата
//     if p1 == verifier.certificate.agg_point && p2 == verifier.certificate.agg_point {
//         println!("Проверка с agg_point из сертификата: УСПЕХ");
//     } else {
//         println!("WARNING: Вычисленные p1/p2 не совпадают с agg_point из сертификата");
//     }

//     // Done
//     if let (is_verified_matrix_agg_points, is_verified_list_agg_points, 
//             is_verified_bit_proves, is_verified_agg_point_hash, 
//             is_verified_signature) = is_verified {
//         println!("\n========================================");
//         println!("РЕЗУЛЬТАТЫ ВЕРИФИКАЦИИ:");
//         println!("========================================");
//         println!("matrix_points_agg == agg_point: {}", 
//                  if is_verified_matrix_agg_points {"УСПЕХ"} else {"ОШИБКА"});
//         println!("list_points_agg + bit_proves_agg == agg_point: {}", 
//                  if is_verified_list_agg_points {"УСПЕХ"} else {"ОШИБКА"});
//         println!("bit_proves верифицированы (Range Proof): {}", 
//                  if is_verified_bit_proves {"УСПЕХ"} else {"ОШИБКА"});
//         println!("hash(agg_point) == agg_point_hash: {}", 
//                  if is_verified_agg_point_hash {"УСПЕХ"} else {"ОШИБКА"});
//         println!("signature verified: {}", 
//                  if is_verified_signature {"УСПЕХ"} else {"ОШИБКА"});
//         println!("Проверка ключей верификации (h_main == h_agg): {}", 
//                  if h_main == &h_agg {"УСПЕХ"} else {"ОШИБКА"});
//         println!("Range Proofs для всех клиентов: {}", 
//                  if all_range_proofs_verified {"УСПЕХ"} else {"ОШИБКА"});
//         println!("Итоговая проверка p1 == p2: {}", 
//                  if p1 == p2 {"УСПЕХ"} else {"ОШИБКА"});
//         println!("========================================");
//     }

//     Ok(())
// }

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

use welsib_smpc::helpers::arg_conf::Config;
use welsib_smpc::verifier::print_help::print_help;
use welsib_smpc::verifier::arguments::WelsibVerifierArguments;
use welsib_smpc::helpers::pipe_certificate::StdInCertificate;
use welsib_smpc::verifier::Verifier;

// Верификация сертификата созданного SMPC сервером
fn main() -> std::io::Result<()> {
    // Init
    let arguments = WelsibVerifierArguments::init();
    if arguments.need_help() {
        print_help();
        return Ok(());
    }
    
    let stdin_certificate = StdInCertificate::read()?;
    let config = Config::read(arguments.get_config_filename()?)?;

    // Run
    let mut verifier = Verifier::new(&config, &stdin_certificate)?;
    let is_verified = verifier.run()?;

    // Done - вывод результатов всех проверок
    if let (
        is_verified_matrix_agg_points,
        is_verified_list_agg_points, 
        is_verified_bit_proves,
        is_verified_agg_point_hash, 
        is_verified_signature,
        is_verified_h_keys,
        is_verified_all_range_proofs,
        is_verified_p1_eq_p2,
        is_verified_agg_point_match
    ) = is_verified {
        println!("\n========================================");
        println!("РЕЗУЛЬТАТЫ ВЕРИФИКАЦИИ:");
        println!("========================================");
        println!("matrix_points_agg == agg_point: {}", 
                 if is_verified_matrix_agg_points {"УСПЕХ"} else {"ОШИБКА"});
        println!("list_points_agg + bit_proves_agg == agg_point: {}", 
                 if is_verified_list_agg_points {"УСПЕХ"} else {"ОШИБКА"});
        println!("bit_proves верифицированы (Range Proof): {}", 
                 if is_verified_bit_proves {"УСПЕХ"} else {"ОШИБКА"});
        println!("hash(agg_point) == agg_point_hash: {}", 
                 if is_verified_agg_point_hash {"УСПЕХ"} else {"ОШИБКА"});
        println!("signature verified: {}", 
                 if is_verified_signature {"УСПЕХ"} else {"ОШИБКА"});
        println!("Проверка ключей верификации (h_main == h_agg): {}", 
                 if is_verified_h_keys {"УСПЕХ"} else {"ОШИБКА"});
        println!("Range Proofs для всех клиентов: {}", 
                 if is_verified_all_range_proofs {"УСПЕХ"} else {"ОШИБКА"});
        println!("Итоговая проверка p1 == p2: {}", 
                 if is_verified_p1_eq_p2 {"УСПЕХ"} else {"ОШИБКА"});
        println!("Проверка с agg_point из сертификата: {}", 
                 if is_verified_agg_point_match {"УСПЕХ"} else {"ОШИБКА"});
        println!("========================================");
    }

    Ok(())
}