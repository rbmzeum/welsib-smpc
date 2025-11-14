use crate::server::WelsibContext;
use crate::server::context::WelsibState;
use crate::server::{context::calculation::Calculation, Encode, Decode, Aggregate};
use crate::smpc::request::SMPCRequest;
use crate::smpc::response::handshake::HandshakeResponseAttributes;
use crate::smpc::response::receive_slot::ReceiveSlotResponseAttributes;
use crate::smpc::response::{SMPCResponse, ResponseStatus};
// use crate::smpc::WelsibDtoInterface;
use crate::smpc::request::receive_slot::ReceiveSlotRequestAttributes;
use std::time::{SystemTime, UNIX_EPOCH};
// use esig::{sign, verify};
// use esig::hash::hash;
// use esig::Signature;
use welsib_u512_ec::verify::welsib_verify;
use crate::hash::hash;
use welsib_u512_ec::sign::Signature;
use crate::base64::safe_decode;
use crate::smpc::slot::{Slot, SlotType};

impl WelsibContext {
    pub fn do_receive_slot(&mut self) {
        // println!("DEBUG DO Receive slot");
        crate::d(format!("DEBUG Do Receive slot"));
        crate::dd(format!("DEBUG Do Receive slot"), "receive_slot");
        let mut smpc_receive_slot_response_command = None;
        // создать обработчик команды (принять слот и поместить в соответствующий слот сервера
        // и ответить клиенту о статусе операции
        // Переключить на состояние обрабатывающее Send запрос (провалидировать запрос от клиента с учётом handshake.nonce_sig)
        let next_state = if let Some(smpc_request) = self.smpc_request() {
            crate::dd(format!("DEBUG Do Receive slot (smpc_request)"), "receive_slot");
            if let Some(receive_slot_request_attr) = ReceiveSlotRequestAttributes::from_json(&smpc_request.attributes()) {
                crate::dd(format!("DEBUG Do Receive slot (receive_slot_request_attr)"), "receive_slot");
                // проверить, что запрос пришёл от клиента в отведённый интервал времени (отсеять подачу устаревших перехваченных MiTM значений)
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() / 8000; // div 8 seconds
                let nonce_sig_bytes = safe_decode(&receive_slot_request_attr.nonce_sig);
                if nonce_sig_bytes.len() == 128 {
                    let nonce_sig = Signature::from_be_bytes(&nonce_sig_bytes);
                    let verify_key = self.keypair.get_public_key();
                    if welsib_verify(&hash(&(now).to_be_bytes().to_vec()), &nonce_sig, &verify_key) ||
                        welsib_verify(&hash(&(now-1).to_be_bytes().to_vec()), &nonce_sig, &verify_key) // previous interval
                    { // Проверка того, что команда выполнилась в отведённый интервал прошла успешно
                        let request_client_signature = safe_decode(&receive_slot_request_attr.signature);
                        if request_client_signature.len() == 128 {
                            let signature = Signature::from_be_bytes(&request_client_signature);
                            // println!("Nonce sig bytes:\n{:?}\n{:?}", &nonce_sig_bytes, &nonce_sig.to_be_bytes());
                            crate::dd(format!("Nonce sig bytes:\n{:?}\n{:?}", &nonce_sig_bytes, &nonce_sig.to_be_bytes()), "receive_slot");
                            // TODO: отладить код в глубину
                            let slot_type_byte = match receive_slot_request_attr.slot_type { SlotType::Controller => 1u8, SlotType::Main => 2, SlotType::Value => 3, SlotType::Key => 4, _ => 0};
                            let slot_index_bytes = receive_slot_request_attr.slot_index.to_be_bytes().to_vec();
                            let bytes = [
                                receive_slot_request_attr.nonce_sig.as_bytes().to_vec(),
                                vec![slot_type_byte],
                                slot_index_bytes,
                                receive_slot_request_attr.client_index.to_be_bytes().to_vec(),
                            ].concat();
                            let slot_attr_hash = hash(&bytes);

                            let public_keys = self.config.get_public_keys();
                            let client_verify_key = public_keys.get(receive_slot_request_attr.client_index);
                            // println!("DEBUG send slot (client_verify_key): {:?}", &client_verify_key);
                            crate::dd(format!("DEBUG send slot (client_verify_key):\n{:?}", &client_verify_key), "receive_slot");
                            if let Some(client_verify_key) = client_verify_key {
                                // println!("DEBUG send slot inner (client_verify_key): {:?}", &client_verify_key);
                                crate::dd(format!("DEBUG send slot inner (client_verify_key): {:?}", &client_verify_key), "receive_slot");
                                // FIXME: отладить параметры для verify и найти ошибку
                                // println!("DEBUG VERIFY Hash: {:?}", &slot_attr_hash);
                                // println!("DEBUG VERIFY Key: {:?}", &client_verify_key);
                                // println!("DEBUG VERIFY Signature: {:?}", &signature);
                                if welsib_verify(&slot_attr_hash, &signature, &client_verify_key) {
                                    // println!("DEBUG send slot (verify): {:?}", &client_verify_key);
                                    crate::dd(format!("DEBUG send slot (verify): {:?}", &client_verify_key), "receive_slot");
                                    if let Ok(smpc_field) = self.smpc_field.lock() {
                                        // прочитать слот из памяти сервера (контролёра)
                                        match receive_slot_request_attr.slot_type {
                                            SlotType::Controller => {
                                                crate::dd(format!("DEBUG SlotType::Controller"), "receive_slot");
                                                // Вернуть слоты контролёра
                                                if let Some(slot_point) = public_keys.get(receive_slot_request_attr.slot_index) {
                                                    if let Some(slot) = smpc_field.get_random_control_slot(slot_point.clone()) {
                                                        // подготовить ответ клиенту
                                                        let private_key = self.keypair.get_secret_key();
                                                        let smpc_receive_slot_response_attributes = ReceiveSlotResponseAttributes::new(ResponseStatus::Success, slot, &signature); // привяка ответа к сигнатуре запроса
                                                        smpc_receive_slot_response_command = Some(SMPCResponse::make(smpc_receive_slot_response_attributes.to_json(), &private_key));
                                                        WelsibState::AwaitOutput
                                                    } else {
                                                        WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                                    }
                                                } else {
                                                    WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                                }
                                            },
                                            SlotType::Main => {
                                                crate::d(format!("DEBUG SlotType::Main"));
                                                // Вернуть main-слоты владельца суммы
                                                if let Some(slot_point) = public_keys.get(receive_slot_request_attr.slot_index) {
                                                    crate::d(format!("DEBUG SlotType::Main (slot_point): {:?}\n{:?}", &slot_point, &smpc_field));
                                                    if let Some(slot) = smpc_field.get_main_client_slot(slot_point.clone()) { // FIXME: здесь не находит нужную запись
                                                        crate::d(format!("DEBUG SlotType::Main (slot): {:?}", &slot));
                                                        // подготовить ответ клиенту
                                                        let private_key = self.keypair.get_secret_key();
                                                        let smpc_receive_slot_response_attributes = ReceiveSlotResponseAttributes::new(ResponseStatus::Success, slot, &signature); // привяка ответа к сигнатуре запроса
                                                        smpc_receive_slot_response_command = Some(SMPCResponse::make(smpc_receive_slot_response_attributes.to_json(), &private_key));
                                                        crate::d(format!("DEBUG SlotType::Main (smpc_receive_slot_response_command): {:?}", &smpc_receive_slot_response_command));
                                                        WelsibState::AwaitOutput
                                                    } else {
                                                        crate::d(format!("DEBUG SlotType::Main (slot done)"));
                                                        WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                                    }
                                                } else {
                                                    crate::d(format!("DEBUG SlotType::Main (slot_point done)"));
                                                    WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                                }
                                            },
                                            SlotType::Value => {
                                                // TODO: добавить с учётом новой формулы соединяющей value с RANGE proof
                                                crate::d(format!("DEBUG SlotType::Value"));
                                                // Вернуть слоты клиентов (участников с подмешиванием приватных значений: сумма владельца суммы и слагаемые остальных участников)
                                                if let Some(slot_point) = public_keys.get(receive_slot_request_attr.slot_index) {
                                                    if let Some(slot) = smpc_field.get_client_slot(slot_point.clone(), receive_slot_request_attr.client_index) {
                                                        // подготовить ответ клиенту
                                                        let private_key = self.keypair.get_secret_key();
                                                        let smpc_receive_slot_response_attributes = ReceiveSlotResponseAttributes::new(ResponseStatus::Success, slot, &signature); // привяка ответа к сигнатуре запроса
                                                        smpc_receive_slot_response_command = Some(SMPCResponse::make(smpc_receive_slot_response_attributes.to_json(), &private_key));
                                                        WelsibState::AwaitOutput
                                                    } else {
                                                        WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                                    }
                                                } else {
                                                    WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                                }
                                            },
                                            SlotType::Key => {
                                                // TODO: клиент запрашивает у сервера слот
                                                crate::dd(format!("DEBUG SlotType::Key"), "receive_slot");
                                                // Вернуть key-слоты клиентов
                                                if let Some(slot_point) = public_keys.get(receive_slot_request_attr.slot_index) {
                                                    crate::dd(format!("DEBUG SlotType::Key (slot_point)"), "receive_slot");
                                                    if let Some(key_slot) = smpc_field.get_random_client_range_key_slot(slot_point.clone(), receive_slot_request_attr.client_index) {
                                                        crate::dd(format!("DEBUG SlotType::Key (key_slot)"), "receive_slot");
                                                        // подготовить ответ клиенту
                                                        let private_key = self.keypair.get_secret_key();
                                                        let smpc_receive_slot_response_attributes = ReceiveSlotResponseAttributes::new(ResponseStatus::Success, key_slot, &signature); // привяка ответа к сигнатуре запроса
                                                        smpc_receive_slot_response_command = Some(SMPCResponse::make(smpc_receive_slot_response_attributes.to_json(), &private_key));
                                                        WelsibState::AwaitOutput
                                                    } else {
                                                        WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                                    }
                                                } else {
                                                    WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                                }
                                            },
                                            _ => {
                                                WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                            }
                                        }
                                    } else {
                                        WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                    }
                                } else {
                                    // println!("Receive slot (verify error)");
                                    crate::d(format!("Receive slot (verify error)"));
                                    WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                }
                            } else {
                                WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                            }
                        } else {
                            // println!("Request receive slot signature is wrong:\n{:?}", &request_client_signature);
                            crate::d(format!("Request receive slot signature is wrong:\n{:?}", &request_client_signature));
                            // return ErrorAttributes::new("Неверный объём данных цифровой подписи (request sell signature ).").to_json::<ErrorAttributes>();
                            WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                        }
                    } else {
                        WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                    }
                } else {
                    WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                }
            } else {
                WelsibState::Done // TODO: ответить клиенту со статусом ошибка
            }
        } else {
            WelsibState::Done // TODO: ответить клиенту со статусом ошибка
        };

        if let Some(smpc_receive_slot_response_command) = smpc_receive_slot_response_command {
            self.set_smpc_response(smpc_receive_slot_response_command);
        }
        self.set_state(next_state);
    }
}
