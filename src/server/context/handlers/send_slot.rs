use crate::server::WelsibContext;
use crate::server::context::WelsibState;
use crate::server::{context::calculation::Calculation, Encode, Decode, Aggregate};
use crate::smpc::request::SMPCRequest;
use crate::smpc::response::handshake::HandshakeResponseAttributes;
use crate::smpc::response::send_slot::SendSlotResponseAttributes;
use crate::smpc::response::{SMPCResponse, ResponseStatus};
// use crate::smpc::WelsibDtoInterface;
use crate::smpc::request::send_slot::SendSlotRequestAttributes;
use std::time::{SystemTime, UNIX_EPOCH};
// use esig::{sign, verify};
// use esig::hash::hash;
// use esig::Signature;
use crate::hash::hash;
use welsib_u512::u512::U512;
use welsib_u512_ec::point::Point;
use welsib_u512_ec::sign::Signature;
use crate::base64::safe_decode;
use crate::smpc::slot::{Slot, SlotType};
use welsib_u512_ec::verify::welsib_verify;

impl WelsibContext {
    pub fn do_send_slot(&mut self) {
        // println!("DEBUG DO Send slot");
        let mut smpc_send_slot_response_command = None;
        // создать обработчик команды (принять слот и поместить в соответствующий слот сервера
        // и ответить клиенту о статусе операции
        // Переключить на состояние обрабатывающее Send запрос (провалидировать запрос от клиента с учётом handshake.nonce_sig)
        let next_state = if let Some(smpc_request) = self.smpc_request() {
            if let Some(send_slot_request_attr) = SendSlotRequestAttributes::from_json(&smpc_request.attributes()) {
                // проверить, что запрос пришёл от клиента в отведённый интервал времени (отсеять подачу устаревших перехваченных MiTM значений)
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() / 8000; // div 8 seconds
                let nonce_sig_bytes = safe_decode(&send_slot_request_attr.nonce_sig);
                if nonce_sig_bytes.len() == 128 {
                    let nonce_sig = Signature::from_be_bytes(&nonce_sig_bytes);
                    let verify_key = self.keypair.get_public_key();
                    if welsib_verify(&hash(&(now).to_be_bytes().to_vec()), &nonce_sig, &verify_key) || 
                        welsib_verify(&hash(&(now-1).to_be_bytes().to_vec()), &nonce_sig, &verify_key) // previous interval
                    { // Проверка того, что команда выполнилась в отведённый интервал прошла успешно
                        let request_client_signature = safe_decode(&send_slot_request_attr.signature);
                        if request_client_signature.len() == 128 {
                            let signature = Signature::from_be_bytes(&request_client_signature);
                            // println!("Nonce sig bytes:\n{:?}\n{:?}", &nonce_sig_bytes, &nonce_sig.to_be_bytes());
                            // TODO: отладить код в глубину

                            let slot_type_byte = match send_slot_request_attr.slot_type { SlotType::Controller => 1u8, SlotType::Main => 2, SlotType::Value => 3, _ => 0};
                            let slot_index_bytes = send_slot_request_attr.slot_index.to_be_bytes().to_vec();
                            let bytes = [
                                send_slot_request_attr.nonce_sig.as_bytes().to_vec(),
                                vec![slot_type_byte],
                                slot_index_bytes,
                                send_slot_request_attr.slot_bytes.clone(),
                                send_slot_request_attr.client_index.to_be_bytes().to_vec(),
                            ].concat();
                            let slot_attr_hash = hash(&bytes);

                            let public_keys = self.config.get_public_keys();
                            let client_verify_key = public_keys.get(send_slot_request_attr.client_index); // ключ отправителя
                            // println!("DEBUG send slot (client_verify_key): {:?}", &client_verify_key);
                            if let Some(client_verify_key) = client_verify_key {
                                // println!("DEBUG send slot inner (client_verify_key): {:?}", &client_verify_key);
                                // FIXME: отладить параметры для verify и найти ошибку
                                // println!("DEBUG VERIFY Hash: {:?}", &slot_attr_hash);
                                // println!("DEBUG VERIFY Key: {:?}", &client_verify_key);
                                // println!("DEBUG VERIFY Signature: {:?}", &signature);
                                if welsib_verify(&slot_attr_hash, &signature, &client_verify_key) {
                                    // println!("DEBUG send slot (verify): {:?}", &client_verify_key);
                                    if let Ok(mut smpc_field) = self.smpc_field.lock() {
                                        // записать слот в память сервера (контролёра)
                                        let slot = Slot::from_bytes(send_slot_request_attr.slot_bytes);
                                        // TODO: сохранить слот в зависимости от типа слота
                                        match send_slot_request_attr.slot_type {
                                            SlotType::Controller => {
                                                // Контролёр - сервер, поэтому клиент не может отправить слот с типом контролёра
                                                // если такой тип прилетает от клиента, значит клиент делает что-то не так
                                                WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                            },
                                            SlotType::Main => {
                                                // принять Main слоты владельца суммы
                                                if let Some(rcpt_verify_key) = public_keys.get(send_slot_request_attr.slot_index) {
                                                    smpc_field.set_main_client_slot( rcpt_verify_key.clone(), slot);
                                                    // подготовить ответ клиенту
                                                    let private_key = self.keypair.get_secret_key();
                                                    let smpc_send_slot_response_attributes = SendSlotResponseAttributes::new(ResponseStatus::Success, &signature); // привяка ответа к сигнатуре запроса
                                                    smpc_send_slot_response_command = Some(SMPCResponse::make(smpc_send_slot_response_attributes.to_json(), &private_key));
                                                    WelsibState::AwaitOutput
                                                } else {
                                                    WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                                }
                                            },
                                            SlotType::Value => {
                                                smpc_field.set_client_slot(client_verify_key.clone(), send_slot_request_attr.slot_index, slot);
                                                // подготовить ответ клиенту
                                                let private_key = self.keypair.get_secret_key();
                                                let smpc_send_slot_response_attributes = SendSlotResponseAttributes::new(ResponseStatus::Success, &signature); // привяка ответа к сигнатуре запроса
                                                smpc_send_slot_response_command = Some(SMPCResponse::make(smpc_send_slot_response_attributes.to_json(), &private_key));
                                                WelsibState::AwaitOutput
                                            }
                                            _ => {
                                                WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                            }
                                        }
                                    } else {
                                        WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                    }
                                } else {
                                    // println!("Send slot (verify error)");
                                    WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                }
                            } else {
                                WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                            }
                        } else {
                            // println!("Request send slot signature is wrong:\n{:?}", &request_client_signature);
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

        if let Some(smpc_send_slot_response_command) = smpc_send_slot_response_command {
            self.set_smpc_response(smpc_send_slot_response_command);
        }
        self.set_state(next_state);
    }
}
