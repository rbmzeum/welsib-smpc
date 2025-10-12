pub mod handlers;
pub mod runner;
pub mod calculation;

use super::state::WelsibState;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use crate::helpers::arg_key::Keypair;
use crate::server::Dispatcher;
use crate::helpers::welsib_stream::WelsibStream;
use crate::http::welsib_http_request::WelsibHttpRequest;
use crate::http::welsib_http_response::WelsibHttpResponse;
use crate::smpc::request::SMPCRequest;
use crate::smpc::response::SMPCResponse;
use super::smpc_field::SMPCField;
use runner::Runner;
use calculation::Calculation;
use crate::helpers::arg_conf::Config;

pub struct WelsibContext {
    state: WelsibState,
    stream: Option<Arc<Mutex<WelsibStream>>>,
    config: Config,
    keypair: Keypair,
    input: Vec<u8>,                           // сырые данные поступившие от клиента
    // request: Option<WelsibHttpRequest>, // сформированный объект запроса на основе данных из self.input
    // response: Option<WelsibHttpResponse>, // сформированный объект ответа, который может менять по мере передачи контекста между обработчиками
    smpc_request: Option<SMPCRequest>,
    smpc_response: Option<SMPCResponse>,
    smpc_field: Arc<Mutex<SMPCField>>, // Поле для конфиденциальных многосторонних вычислений
    runners: Arc<Mutex<VecDeque<Runner>>>, // Доступные вычислители (количество от 1 до --concurrency=n из аргумента)
    planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>, // Список запланированых вычислений для свободных Runner: Encode, Decode, Aggregate
    dispatcher: Arc<Mutex<Dispatcher>>, // доступ к диспетчеру из контекста
    is_pub: Arc<Mutex<bool>>, // публиковать ключи контролёра созданные в результате многосторонних вычислений
}

impl WelsibContext {
    pub fn new(
        stream: Option<Arc<Mutex<WelsibStream>>>,
        config: Config,
        keypair: Keypair,
        smpc_field: Arc<Mutex<SMPCField>>,
        runners: Arc<Mutex<VecDeque<Runner>>>,
        planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>,
        dispatcher: Arc<Mutex<Dispatcher>>,
        is_pub: Arc<Mutex<bool>>,
    ) -> Self {
        Self {
            state: WelsibState::AwaitBegin,
            stream,
            config,
            keypair,
            input: vec![],
            smpc_request: None,
            smpc_response: None,
            smpc_field,
            runners,
            planned,
            dispatcher,
            is_pub,
        }
    }

    pub fn state(&self) -> WelsibState {
        self.state
    }

    pub fn stream(&self) -> &Option<Arc<Mutex<WelsibStream>>> {
        &self.stream
    }

    pub fn dispatcher(&self) -> &Arc<Mutex<Dispatcher>> {
        &self.dispatcher
    }

    fn push_runner(&self, runner: Runner) {
        self.runners.lock().unwrap().push_front(runner);
    }

    fn push_calculation(&self, calc: impl Calculation + 'static) {
        self.planned.lock().unwrap().push_front(Box::new(calc));
    }

    fn pop_runner(&self) -> Option<Runner> {
        self.runners.lock().unwrap().pop_back()
    }

    fn pop_calculation(&self) -> Option<Box<dyn Calculation + 'static>> {
        self.planned.lock().unwrap().pop_back()
    }

    fn has_calculations(&self) -> bool {
        if let Ok(planned) = self.planned.lock() {
            planned.len() > 0
        } else {
            false
        }
    }

    // pub fn input_bytes(&self) -> &Vec<u8> {
    //     &self.input
    // }

    // pub fn input(&self) -> String {
    //     String::from_utf8(self.input.to_owned())
    //         .unwrap_or("".to_string())
    //         .trim_matches('\0')
    //         .to_string()
    // }

    // pub fn request(&mut self) -> &mut Option<WelsibHttpRequest> {
    //     if self.request.is_none() {
    //         self.request = WelsibHttpRequest::from_string(self.input());
    //     }
    //     &mut self.request
    // }

    // pub fn response(&mut self) -> &Option<WelsibHttpResponse> {
    //     &self.response
    // }

    // pub fn set_response(&mut self, new_response: WelsibHttpResponse) {
    //     self.response = Some(new_response)
    // }

    pub fn set_state(&mut self, new_state: WelsibState) {
        // println!("New state: {:#?}", &new_state);
        self.state = new_state
    }

    pub fn set_input(&mut self, new_input: Vec<u8>) {
        self.input = new_input
    }

    // pub fn input(&self) -> Vec<u8> {
    //     self.input.clone()
    // }

    pub fn set_smpc_request(&mut self, smpc_request: SMPCRequest) {
        self.smpc_request = Some(smpc_request);
    }

    pub fn set_smpc_response(&mut self, smpc_response: SMPCResponse) {
        self.smpc_response = Some(smpc_response);
    }

    pub fn smpc_request(&mut self) -> &mut Option<SMPCRequest> {
        &mut self.smpc_request
    }

    pub fn smpc_response(&mut self) -> &mut Option<SMPCResponse> {
        &mut self.smpc_response
    }
}