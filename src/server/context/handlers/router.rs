use crate::server::WelsibContext;
use crate::server::context::WelsibState;
use crate::smpc::request::SMPCRequest;

impl WelsibContext {
    pub fn do_router(&mut self) {
        // println!("Do router");
        crate::d(format!("DEBUG Do router"));
        let mut input = None;
        let mut smpc_request = None;
        let next_state = match self.stream() {
            Some(stream) => {
                match stream.lock().as_deref_mut() {
                    Ok(stream) => {
                        match stream.read() {
                            Some(res) => {
                                // println!("DEBUG Router: {:?}", &res);
                                crate::d(format!("DEBUG Router:\n{:?}", &res));
                                input = Some(res.clone());

                                smpc_request = SMPCRequest::from_frame(&res);
                                // println!("SMPC Request: {:#?}", &smpc_request);
                                crate::d(format!("DEBUG SMPC Request:\n{:#?}", &smpc_request));
                                // TODO: записать запрос в контекст

                                if let Some(smpc_request) = &smpc_request {
                                    match smpc_request.command().as_str() {
                                        "handshake" => WelsibState::AwaitHandshake,
                                        "send" => WelsibState::AwaitSendSlot, // клиент отпралвять слот на сервер
                                        "send_point_range_verification_key" => WelsibState::AwaitSendPointRangeVerificationKey,
                                        "send_bit_proof" => WelsibState::AwaitSendBitProof,
                                        "send_point_matrix" => WelsibState::AwaitSendPointMatrix,
                                        "send_point_list" => WelsibState::AwaitSendPointList,
                                        "receive" => WelsibState::AwaitReceiveSlot, // клиент запрашивает слот с сервера
                                        "reset" => WelsibState::AwaitReset, // клиент сообщает серверу о сбросе ранее отправленных этим клиентом значений
                                        _ => {
                                            // eprintln!("Ошибка: неизвестная команда");
                                            WelsibState::Done
                                        },
                                    }
                                } else {
                                    WelsibState::Done
                                }

                                // println!("DEBUG Handshake");
                                // self.push_calculation(Encode::new(self.smpc_field.clone()));
                                // self.push_calculation(Decode::new(self.smpc_field.clone()));
                                // self.push_calculation(Aggregate::new(self.smpc_field.clone()));
                                // // в зависимости от concurrency
                                // loop {
                                //     if self.has_calculations() {
                                //         if let Some(mut runner) = self.pop_runner() {
                                //             runner.run(self.planned.clone());
                                //         } else {
                                //             // подождать освобождение раннера
                                //             sleep(std::time::Duration::from_millis(100));
                                //         }
                                //     } else {
                                //         break;
                                //     }
                                // }
                                // =====

                                // let status = StatusDto::from_frame(&res);
                                // if let Some(status) = status {
                                //     if status.is_ready() {
                                //         let request = HandshakeRequest::new();
                                //         match stream.write(&request.to_frame::<HandshakeRequest>())
                                //         {
                                //             Ok(()) => {
                                //                 let handshake_buffer = stream.read(); // TODO: сделать способ определить что соединение зависло или разорвано и сменить статус в соотвествии с этим, если не произошло восстановления соединения
                                //                 match handshake_buffer {
                                //                     Some(b) => {
                                //                         let res = HandshakeResponse::from_frame(&b);
                                //                         // println!("Handshake response: {:#?}", &res);
                                //                         if let Some(response) = res {
                                //                             let (vk_x, vk_y) = if let Ok(is_dev) = self.is_dev().lock().as_deref() {
                                //                                 if *is_dev { crate::registry::DEV_VERIFY_KEY } else { crate::registry::VERIFY_KEY }
                                //                             } else {
                                //                                 // TODO: предупредить о неисправностях
                                //                                 crate::registry::DEV_VERIFY_KEY
                                //                             };
                                //                             let verify_key = esig::Point {
                                //                                 x: num_bigint::BigInt::parse_bytes(vk_x, 16).unwrap(),
                                //                                 y: num_bigint::BigInt::parse_bytes(vk_y, 16).unwrap(),
                                //                             };
                                //                             if response.verify(
                                //                                 &slice2vec(request.random),
                                //                                 &verify_key,
                                //                             ) {
                                //                                 // Success
                                //                                 println!("Handshake success");
                                //                                 // executor status is enabled
                                //                                 // self.update_has_executor_connected(true);
                                //                                 // self.update_api_request_elapsed_time();
                                //                                 WelsibState::AwaitInitiator
                                //                             } else {
                                //                                 WelsibState::Done
                                //                             }
                                //                         } else {
                                //                             WelsibState::Done
                                //                         }
                                //                     }
                                //                     None => WelsibState::Done,
                                //                 }
                                //             }
                                //             Err(_e) => {
                                //                 // TODO: WelsibState::AwaitHandleWriteError
                                //                 // TODO: WelsibState::AwaitWriteErrorInLog
                                //                 eprintln!("Error");
                                //                 WelsibState::Done
                                //             }
                                //         }
                                //     } else {
                                //         WelsibState::Done
                                //     }
                                // } else {
                                //     WelsibState::Done
                                // }
                                // WelsibState::Done
                            }
                            None => {
                                // eprintln!("Error: Client not ready");
                                crate::d(format!("Error: Client not ready"));
                                WelsibState::Done
                            }
                        }
                    }
                    Err(e) => {
                        // eprintln!("Error do_await_read_request: {:#?}", e);
                        crate::d(format!("Error do_await_read_request: {:#?}", &e));
                        // TODO: WelsibState::AwaitHandleWriteError
                        WelsibState::Done
                    }
                }
            },
            _ => {
                WelsibState::Done
            }
        };
        if let Some(input) = input {
            self.set_input(input);
        }
        if let Some(smpc_request) = smpc_request {
            self.set_smpc_request(smpc_request);
        }
        self.set_state(next_state);
    }
}
