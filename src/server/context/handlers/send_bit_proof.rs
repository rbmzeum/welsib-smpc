use crate::server::WelsibContext;
use crate::server::context::WelsibState;
use crate::server::{context::calculation::Calculation, Encode, Decode, Aggregate};
use crate::smpc::request::SMPCRequest;
use crate::smpc::response::handshake::HandshakeResponseAttributes;
use crate::smpc::response::send_bit_proof::SendBitProofResponseAttributes;
use crate::smpc::response::{SMPCResponse, ResponseStatus};
// use crate::smpc::WelsibDtoInterface;
use crate::smpc::request::send_bit_proof::SendBitProofRequestAttributes;
use std::time::{SystemTime, UNIX_EPOCH};
// use esig::{sign, verify, Point};
// use esig::hash::hash;
// use esig::Signature;
use welsib_u512_ec::verify::welsib_verify;
use welsib_u512_ec::elliptic_curve::EllipticCurve;
use crate::hash::hash;
use welsib_u512::u512::U512;
use welsib_u512_ec::point::Point;
use welsib_u512_ec::sign::Signature;
use crate::base64::safe_decode;
use crate::smpc::slot::{Slot, SlotType};
use crate::range_prove::BitProve;

impl WelsibContext {
    pub fn do_send_bit_proof(&mut self) {
        // crate::dd(format!("send_slot: {:?}\n{:x?}", &i, &p.x.get()[0]), "bitprove");
        crate::dd(format!("DEBUG: Do send BitProof"), "range");
        // println!("DEBUG DO Send BitProof");
        let mut smpc_send_bit_proof_response_command = None;
        const RANGE: usize = 128;
        
        let next_state = if let Some(smpc_request) = self.smpc_request() {
            if let Some(send_bit_proof_request_attr) = SendBitProofRequestAttributes::from_json(&smpc_request.attributes()) {
                // Проверка временного интервала (аналогично send_point_matrix)
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() / 8000;
                let nonce_sig_bytes = safe_decode(&send_bit_proof_request_attr.nonce_sig);
                
                if nonce_sig_bytes.len() == 128 {
                    let nonce_sig = Signature::from_be_bytes(&nonce_sig_bytes);
                    let verify_key = self.keypair.get_public_key();
                    
                    if welsib_verify(&hash(&(now).to_be_bytes().to_vec()), &nonce_sig, &verify_key) || 
                       welsib_verify(&hash(&(now-1).to_be_bytes().to_vec()), &nonce_sig, &verify_key) {
                        
                        let request_client_signature = safe_decode(&send_bit_proof_request_attr.signature);
                        if request_client_signature.len() == 128 {
                            let signature = Signature::from_be_bytes(&request_client_signature);

                            // Декодируем bit_proof из base64
                            let bit_proof_frame = safe_decode(&send_bit_proof_request_attr.bit_proof_base64);
                            
                            // Подготовка данных для верификации подписи
                            let bytes = [
                                send_bit_proof_request_attr.nonce_sig.as_bytes().to_vec(),
                                bit_proof_frame.clone(),
                                send_bit_proof_request_attr.bit_index.to_be_bytes().to_vec(),
                                send_bit_proof_request_attr.client_index.to_be_bytes().to_vec(),
                            ].concat();
                            let bit_proof_attr_hash = hash(&bytes);
                            
                            let public_keys = self.config.get_public_keys();
                            let client_verify_key = public_keys.get(send_bit_proof_request_attr.client_index);
                            
                            if let Some(client_verify_key) = client_verify_key {
                                if welsib_verify(&bit_proof_attr_hash, &signature, &client_verify_key) {
                                    // Десериализация BitProve
                                    let curve = EllipticCurve::make_curve_welsib();
                                    if let Some(bit_prove) = BitProve::from_bytes(&bit_proof_frame, curve.g.clone()) {
                                        if let Ok(mut smpc_field) = self.smpc_field.lock() {
                                            // При получении bit_proof
                                            crate::dd(format!("DEBUG solution: Получен bit_proof {}:{:?} от клиента {:?}", 
                                                            &send_bit_proof_request_attr.bit_index, &bit_prove, &client_verify_key.x), "solution");
                                            // Сохраняем битпруф
                                            smpc_field.set_bit_proof(
                                                client_verify_key.clone(),
                                                send_bit_proof_request_attr.bit_index,
                                                bit_prove
                                            );
                                            
                                            // Проверяем, собраны ли все битпруфы (ожидаем 128 для диапазона u128)
                                            // if smpc_field.are_all_bit_proofs_collected(client_verify_key, RANGE) {
                                            //     // Собираем все битпруфы в единый вектор
                                            //     if let Some(bit_proofs) = smpc_field.collect_bit_proofs(client_verify_key, RANGE) {
                                            //         // Вычисляем confidential_value из собранных битпруфов
                                            //         let confidential_value = crate::range_prove::range_point_from_bit_proofs(
                                            //             &curve, 
                                            //             &bit_proofs, 
                                            //             RANGE
                                            //         );
                                                    
                                            //         // Сохраняем вычисленное confidential_value
                                            //         smpc_field.set_confidential_value(
                                            //             client_verify_key.clone(),
                                            //             confidential_value
                                            //         );
                                                    
                                            //         // TODO: В будущем здесь будет верификация диапазона
                                            //         // с использованием range_verification_key, который
                                            //         // должен быть уже сохранен через send_point с типом RangeVerificationKey
                                            //     }
                                            // }
                                            
                                            // Подготовка ответа клиенту
                                            let private_key = self.keypair.get_secret_key();
                                            let smpc_send_bit_proof_response_attributes = 
                                                SendBitProofResponseAttributes::new(ResponseStatus::Success, &signature);
                                            
                                            smpc_send_bit_proof_response_command = Some(
                                                SMPCResponse::make(
                                                    smpc_send_bit_proof_response_attributes.to_json(), 
                                                    &private_key
                                                )
                                            );
                                            
                                            WelsibState::AwaitOutput
                                        } else {
                                            WelsibState::Done
                                        }
                                    } else {
                                        WelsibState::Done
                                    }
                                } else {
                                    WelsibState::Done
                                }
                            } else {
                                WelsibState::Done
                            }
                        } else {
                            WelsibState::Done
                        }
                    } else {
                        WelsibState::Done
                    }
                } else {
                    WelsibState::Done
                }
            } else {
                WelsibState::Done
            }
        } else {
            WelsibState::Done
        };
        
        if let Some(smpc_send_bit_proof_response_command) = smpc_send_bit_proof_response_command {
            self.set_smpc_response(smpc_send_bit_proof_response_command);
        }
        self.set_state(next_state);
    }
}
