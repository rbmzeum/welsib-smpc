use super::context::WelsibContext;
use super::state::WelsibState;
use std::collections::HashMap;
use std::io::Error;
use std::sync::{Arc, Mutex};
use std::thread::{JoinHandle, Thread};
use std::{
    collections::VecDeque,
    thread::{sleep, spawn, ThreadId},
    time::Duration,
};

#[derive(Debug)]
pub struct Dispatcher {
    handlers: Arc<Mutex<VecDeque<JoinHandle<Result<(), Error>>>>>,
    threads: Arc<Mutex<HashMap<ThreadId, Thread>>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        let handlers = Arc::new(Mutex::new(VecDeque::<JoinHandle<Result<(), Error>>>::new()));
        let hndlrs = handlers.clone();
        let threads = Arc::new(Mutex::new(HashMap::new()));
        let thrds = threads.clone();
        let dispatcher = spawn(move || -> std::io::Result<()> {
            loop {
                // crate::d(format!("LOOP"));
                match hndlrs.lock().as_deref_mut() {
                    Ok(handlers) => {
                        while handlers.len() > 0 {
                            crate::d(format!("Handlers len: {}", handlers.len()));
                            let _ = match handlers.pop_back() {
                                Some(handler) => {
                                    let thread = handler.thread();
                                    // let name = thread.name();
                                    match thrds.lock().as_deref_mut() {
                                        Ok(threads) => {
                                            threads.insert(thread.id(), thread.to_owned());
                                            // FIXME: надо чистить массив от выполнившихся тредов
                                        }
                                        Err(e) => {
                                            crate::d(format!("Error threads: {:#?}", e));
                                        }
                                    };
                                    crate::d(format!("Thread id: {:#?}", &thread.id()));
                                    // let x = std::thread::current().id();
                                    // let x = thread.id();
                                }
                                None => {
                                    crate::d(format!(" Warning: не удалось извлечь обработчик"));
                                    // Ok(())
                                }
                            };
                        }
                    }
                    Err(e) => {
                        crate::d(format!("Error [handlers.push_front(handler)]: {:#?}", &e));
                    }
                };

                sleep(Duration::from_millis(1));
            }
        });

        let dispatcher_thread = dispatcher.thread();
        crate::d(format!("Dispatcher thread: {:#?}", dispatcher_thread));

        Self { handlers, threads }
    }

    pub fn handle(&mut self, context: WelsibContext) -> std::io::Result<()> {
        let context = Arc::new(Mutex::new(context));
        let threads = self.threads.clone();
        let handler = spawn(move || -> std::io::Result<()> {
            match context.lock().as_deref_mut() {
                Ok(context) => {
                    crate::d(format!("Handle context: {:#?}", &context.state()));
                    while context.state() != WelsibState::Done {
                        Self::dispatch(context);
                        // TODO: если context.stream() отсоединился, то завершить цикл
                        // обработать context.stream().take_error(), и при необходимости выйти из цикла
                    }
                }
                Err(e) => {
                    crate::d(format!("Error (handle request): {:#?}", e));
                }
            };

            match threads.lock().as_deref_mut() {
                Ok(threads) => {
                    threads.remove(&std::thread::current().id()); // TODO: сохранять так же время запуска процесса, и выполнять стратегию удаления процесса из списка, если связь потеряна или протокол требует close, так же процесс может завершиться операционной системой принудительно и не дойти до этого места очистки, надо учесть и это
                    Ok(())
                }
                Err(e) => {
                    crate::d(format!("Error {:#?}", &e));
                    Ok(()) // FIXME: вернуть Error
                }
            }
        });

        match self.handlers.lock().as_deref_mut() {
            Ok(handlers) => {
                handlers.push_front(handler);
                crate::d(format!("Pushed handler: {}", handlers.len()));
            }
            Err(e) => {
                crate::d(format!("Error [handlers.push_front(handler)]: {:#?}", e));
            }
        };

        Ok(())
    }

    pub fn threads(&self) -> &Arc<Mutex<HashMap<ThreadId, Thread>>> {
        &self.threads
    }

    fn dispatch(context: &mut WelsibContext) {
        // Типы запросов:
        match context.state() {
            // Ограничение на размер запроса 4096 байт.
            WelsibState::AwaitBegin => context.do_begin(), // начальный роутинг, разделяет web и system
            WelsibState::AwaitRouter => context.do_router(),
            WelsibState::AwaitHandshake => context.do_handshake(),
            WelsibState::AwaitSendSlot => context.do_send_slot(),
            // WelsibState::AwaitSendPointKey => context.do_send_point_key(),
            WelsibState::AwaitSendPointRangeVerificationKey => context.do_send_point_range_verification_key(),
            WelsibState::AwaitSendPointMatrix => context.do_send_point_matrix(),
            WelsibState::AwaitSendPointList => context.do_send_point_list(),
            WelsibState::AwaitOutput => context.do_output(),
            WelsibState::AwaitReceiveSlot => context.do_receive_slot(),
            WelsibState::AwaitReset => context.do_reset(),
            // TODO: здесь перечислить обработчики
            _ => {
                crate::d(format!("Unknown WelsibState"));
                context.set_state(WelsibState::Done);
            }
        };
    }
}
