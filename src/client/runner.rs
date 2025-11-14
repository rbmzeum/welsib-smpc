use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use crate::client::Calculation;
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
        crate::dd(format!("DEBUG (run)"), "run");
        // создаёт отдельный процесс и по его завершению восстанавливает раннер
        let renew = |runners: Arc<Mutex<VecDeque<Runner>>>| {
            crate::dd(format!("DEBUG (run, renew)"), "run");
            if let Ok(mut runners_guard) = runners.lock() {
                runners_guard.push_front(Runner::new(runners.clone()));
            }
        };

        let has_renew = if let Ok(mut planned) = planned.lock() {
            crate::dd(format!("DEBUG (run, has_renew)"), "run");
            if planned.len() > 0 {
                crate::dd(format!("DEBUG (run, planned.len() > 0)"), "run");
                if let Some(method) = planned.pop_back() {
                    crate::dd(format!("DEBUG (run, method)"), "run");
                    let runners = self.runners.clone();
                    let threadid = self.threadid.clone();
                    let thread = self.thread.clone();
                    let handler = Some(spawn(move || -> std::io::Result<()> {
                        crate::dd(format!("DEBUG (run, handler)"), "run");
                        crate::dd(format!("DEBUG (run, before calculation)"), "run");
                        method.calculation();
                        crate::dd(format!("DEBUG (run, after calculation)"), "run");
                        renew(runners);
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