use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use crate::server::Calculation;
// use super::calculation;
use std::io::Error;
use std::thread::{sleep, spawn, ThreadId, JoinHandle, Thread};

pub struct Runner {
    runners: Arc<Mutex<VecDeque<Runner>>>,
    handler: Option<JoinHandle<Result<(), Error>>>,
    threadid: Arc<Mutex<Option<ThreadId>>>,
    thread: Arc<Mutex<Option<Thread>>>,
}

impl Runner {
    pub fn new(runners: Arc<Mutex<VecDeque<Runner>>>) -> Self {
        Runner {
            runners,
            handler: None,
            threadid: Arc::new(Mutex::new(None)),
            thread: Arc::new(Mutex::new(None)),
        }
    }

    pub fn run(&mut self, planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>) {
        // создаёт отдельный процесс и по его завершению восстанавливает раннер
        let renew = |runners: Arc<Mutex<VecDeque<Runner>>>| {
            if let Ok(mut runners_guard) = runners.lock() {
                runners_guard.push_front(Runner::new(runners.clone()));
            }
        };

        let has_renew = if let Ok(mut planned) = planned.lock() {
            if planned.len() > 0 {
                if let Some(method) = planned.pop_back() {
                    let runners = self.runners.clone();
                    let threadid = self.threadid.clone();
                    let thread = self.thread.clone();
                    let handler = Some(spawn(move || -> std::io::Result<()> {
                        method.calculation();
                        renew(runners);
                        // TODO: send event (observer), для запуска процесса отправки сообщения по сети на сервер
                        Ok(())
                    }));
                    if let Some(hdlr) = handler {
                        let thd = hdlr.thread();
                        if let Ok(mut tid) = threadid.lock() {
                            tid.replace(thd.id());
                        }
                        if let Ok(mut t) = thread.lock() {
                            t.replace(thd.to_owned());
                        }
                        self.handler = Some(hdlr);
                    }
                }
                false
            } else {
                true
            }
        } else {
            true
        };

        if has_renew {
            // вычислив результат вернуть раннер в список доступных для использования раннеров
            renew(self.runners.clone());
        }
    }

}