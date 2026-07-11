use crate::server::WelsibContext;
use crate::server::context::WelsibState;
use crate::server::{context::calculation::Calculation, Encode, Decode, Aggregate};
use crate::smpc::request::SMPCRequest;
use crate::smpc::response::handshake::HandshakeResponseAttributes;
use crate::smpc::response::send_point::SendPointResponseAttributes;
use crate::smpc::response::{SMPCResponse, ResponseStatus};
// use crate::smpc::WelsibDtoInterface;
use crate::smpc::request::send_point::SendPointRequestAttributes;
use std::time::{SystemTime, UNIX_EPOCH};
// use esig::{sign, verify, Point};
// use esig::hash::hash;
// use esig::Signature;
use welsib_u512_ec::verify::welsib_verify;
use crate::hash::hash;
use welsib_u512::u512::U512;
use welsib_u512_ec::point::Point;
use welsib_u512_ec::sign::Signature;
use crate::base64::safe_decode;
use crate::smpc::slot::{Slot, SlotType};

impl WelsibContext {
    pub fn do_send_point_list(&mut self) {
        // println!("DEBUG DO Send point list");
        let mut smpc_send_point_response_command = None;
        // создать обработчик команды (принять слот и поместить в соответствующий слот сервера
        // и ответить клиенту о статусе операции
        // Переключить на состояние обрабатывающее Send запрос (провалидировать запрос от клиента с учётом handshake.nonce_sig)
        let next_state = if let Some(smpc_request) = self.smpc_request() {
            if let Some(send_point_request_attr) = SendPointRequestAttributes::from_json(&smpc_request.attributes()) {
                // проверить, что запрос пришёл от клиента в отведённый интервал времени (отсеять подачу устаревших перехваченных MiTM значений)
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() / 8000; // div 8 seconds
                let nonce_sig_bytes = safe_decode(&send_point_request_attr.nonce_sig);
                if nonce_sig_bytes.len() == 128 {
                    let nonce_sig = Signature::from_be_bytes(&nonce_sig_bytes);
                    let verify_key = self.keypair.get_public_key();
                    if welsib_verify(&hash(&(now).to_be_bytes().to_vec()), &nonce_sig, &verify_key) || 
                        welsib_verify(&hash(&(now-1).to_be_bytes().to_vec()), &nonce_sig, &verify_key) // previous interval
                    { // Проверка того, что команда выполнилась в отведённый интервал прошла успешно
                        let request_client_signature = safe_decode(&send_point_request_attr.signature);
                        if request_client_signature.len() == 128 {
                            let signature = Signature::from_be_bytes(&request_client_signature);
                            // println!("Nonce sig bytes:\n{:?}\n{:?}", &nonce_sig_bytes, &nonce_sig.to_be_bytes());
                            // TODO: отладить код в глубину
                            let bytes = [
                                send_point_request_attr.nonce_sig.as_bytes().to_vec(),
                                send_point_request_attr.point_bytes.clone(),
                                send_point_request_attr.client_index.to_be_bytes().to_vec(),
                            ].concat();
                            let point_attr_hash = hash(&bytes);

                            let public_keys = self.config.get_public_keys();
                            let client_verify_key = public_keys.get(send_point_request_attr.client_index); // ключ отправителя
                            // println!("DEBUG send point (client_verify_key): {:?}", &client_verify_key);
                            if let Some(client_verify_key) = client_verify_key {
                                // println!("DEBUG send point inner (client_verify_key): {:?}", &client_verify_key);
                                // FIXME: отладить параметры для verify и найти ошибку
                                // println!("DEBUG VERIFY Hash: {:?}", &point_attr_hash);
                                // println!("DEBUG VERIFY Key: {:?}", &client_verify_key);
                                // println!("DEBUG VERIFY Signature: {:?}", &signature);
                                if welsib_verify(&point_attr_hash, &signature, &client_verify_key) {
                                    // println!("DEBUG send point (verify): {:?}", &client_verify_key);
                                    if let Ok(mut smpc_field) = self.smpc_field.lock() {
                                        let point = Point::from_be_bytes(&send_point_request_attr.point_bytes).unwrap(); // TODO: WelsibState::Done // TODO: ответить клиенту со статусом ошибка (вместо unwrap(), обработать ошибку)
                                        // При получении point_list
                                        crate::dd(format!("DEBUG solution: Получена point_list от клиента {:?}: {:?}", 
                                                        &client_verify_key.x, &point.x), "solution");
                                        smpc_field.set_point_list(client_verify_key.clone(), point);
                                        // подготовить ответ клиенту
                                        let private_key = self.keypair.get_secret_key();
                                        let smpc_send_point_response_attributes = SendPointResponseAttributes::new(ResponseStatus::Success, &signature); // привяка ответа к сигнатуре запроса
                                        smpc_send_point_response_command = Some(SMPCResponse::make(smpc_send_point_response_attributes.to_json(), &private_key));
                                        WelsibState::AwaitOutput
                                    } else {
                                        WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                    }
                                } else {
                                    // println!("Send point (verify error)");
                                    WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                                }
                            } else {
                                WelsibState::Done // TODO: ответить клиенту со статусом ошибка
                            }
                        } else {
                            // println!("Request send point signature is wrong:\n{:?}", &request_client_signature);
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

        if let Some(smpc_send_point_response_command) = smpc_send_point_response_command {
            self.set_smpc_response(smpc_send_point_response_command);
        }
        self.set_state(next_state);
    }
}
