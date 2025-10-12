use crate::server::WelsibContext;
use crate::server::context::WelsibState;
use crate::smpc::response::SMPCResponse;
// use crate::smpc::WelsibDtoInterface;

impl WelsibContext {
    pub fn do_output(&mut self) {
        // println!("DEBUG DO Output");
        let smpc_response_bytes = if let Some(smpc_response) = self.smpc_response() {
            Some(smpc_response.to_frame())
        } else {
            None
        };
        let next_state = if let Some(smpc_response_bytes) = smpc_response_bytes {
            match self.stream() {
                Some(stream) => {
                    // println!("DEBUG DO Output: Arc<Mutex<WelsibStream>>");
                    match stream.lock().as_deref_mut() {
                        Ok(stream) => {
                            // println!("DEBUG DO Output: WelsibStream");
                            // TODO: сделать качественную обработку ошибок и возможность дублированной отправки, если соединение не разорвано
                            if let Err(e) = stream.write(&smpc_response_bytes) {
                                // eprintln!("Ошибка: Не удалось отправить ответ на команду ready клиенту:\n{:#?}", e);
                            }
                            // println!("Handshake too");
                            WelsibState::Done
                        }
                        Err(e) => {
                            // eprintln!("Error do_await_read_request: {:#?}", e);
                            // TODO: WelsibState::AwaitHandleWriteError
                            WelsibState::Done
                        }
                    }
                },
                _ => {
                    WelsibState::Done
                }
            }
        } else {
            // eprint!("Ошибка: smpc_response is None");
            WelsibState::Done
        };
        self.set_state(next_state);
    }
}