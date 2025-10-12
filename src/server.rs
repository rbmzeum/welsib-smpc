pub mod print_help;
pub mod arguments;
pub mod connection;
pub mod state;
pub mod context;
pub mod dispatcher;
pub mod smpc_field;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use crate::certificate::Certificate;
use crate::helpers::arg_conf::Config;
use crate::helpers::arg_key::Keypair;
use crate::helpers::welsib_stream::WelsibStream;
use smpc_field::SMPCField;
use arguments::WelsibServerArguments;
use dispatcher::Dispatcher;
use context::WelsibContext;
use context::runner::Runner;
use context::calculation::{Calculation, encode::Encode, decode::Decode, aggregate::Aggregate};
use std::net::TcpListener;
use std::time::Duration;
use std::thread::{sleep, spawn};

#[derive(Clone)]
pub struct Server {
    config: Config,
    arguments: WelsibServerArguments,
    keypair: Keypair,
    dispatcher: Arc<Mutex<Dispatcher>>, // Диспетчер для обработки запросов
    smpc_field: Arc<Mutex<SMPCField>>, // Поле данных для многосторонних вычислений: матрица с шифрованными словами и списки с шифрованными слотами для обмена значениями между участниками
    runners: Arc<Mutex<VecDeque<Runner>>>,
    planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>>,
    is_pub: Arc<Mutex<bool>>, // Флаг общедоступности результатов true, и конфеденциальности false
}

impl Server {
    pub fn new(config: &Config, arguments: &WelsibServerArguments, keypair: Keypair)  -> std::io::Result<Self> {
        // Инициализация флагов
        let is_pub = Arc::new(Mutex::new(arguments.is_pub()));

        // Определение количества участников
        let pk_len = config.get_public_keys().len();
        if pk_len <= 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка, участников не может быть меньше трёх: (1) сумма = (2) единственное слагаемое и (3) контролёр.",
            ));
        }
        let participants = pk_len-1; // за исключением контролёра
        // TODO: build SMPCField (let smpc_field = SMPCFieldBuilder::a(...).b(...).build())
        // TODO: добавить вспомогательный метод get_id_by_point: BTreeMap<p: Point, id: usize>

        // Инициализация поля с шифрованными слотами для конфиденциальных многосторонних вычислений
        let smpc_field = Arc::new(Mutex::new(SMPCField::new()));
        let runners = Arc::new(Mutex::new(VecDeque::new()));
        let planned: Arc<Mutex<VecDeque<Box<dyn Calculation>>>> = Arc::new(Mutex::new(VecDeque::new()));

        let smpc_field_copy = smpc_field.clone();
        if let Ok(mut smpc_field) = smpc_field.lock() {
            smpc_field.create_random_additive_parts(participants, config.get_public_keys(), planned.clone(), smpc_field_copy)?; // SlotType::Controller
        }

        // DEBUG:
        // let calc1 = Encode;
        // let calc2 = Decode;
        // let calc3 = Aggregate;
        // planned.lock().unwrap().push(Box::new(calc1));
        // planned.lock().unwrap().push(Box::new(calc2));
        // planned.lock().unwrap().push(Box::new(calc3));
        // for item in planned.lock().unwrap().iter() {
        //     item.calculation();
        // }
        // ======
        // TODO: создать случайные числа в соответствующих smpc_field слотах и зашифровать через раннеры для клиентов
        // количество клиентов определяется из конфига по количеству публичных ключей config.public_keys.len()-1
        // @see helpers::shifted_random::create_shifted_random и esig::random::create_random_additive_parts
        // let csr = create_shifted_random();
        // if let Some(parts) = create_random_additive_parts(&csr, participants) {
        //     // TODO: зашифровать parts для каждого участника используя параллельных воркеров runner, planned очереди и разместить в smpc_field в соответствующих слотах
        //     println!("Секретные ключи контролёра: {:?}", &parts);
        // } else {
        //     // TODO: ошибка, отсутствуют участники
        // }
        // ======
        // if let Ok(mut planned) = planned.lock() {
        //     planned.push_front(Box::new(Encode {}));
        //     planned.push_front(Box::new(Decode {}));
        //     planned.push_front(Box::new(Aggregate {}));
        // }
        // if let Some(mut runner) = self.pop_runner() {
        //     runner.run(self.planned.clone());
        // }
        // if let Some(mut runner) = self.pop_runner() {
        //     runner.run(self.planned.clone());
        // }
        // if let Some(mut runner) = self.pop_runner() {
        //     runner.run(self.planned.clone());
        // }
        // ======

        Ok(Self {
            config: config.clone(),
            arguments: arguments.clone(),
            keypair,
            dispatcher: Arc::new(Mutex::new(Dispatcher::new())),
            smpc_field,
            runners,
            planned,
            is_pub,
        })
    }

    pub fn run(&mut self) -> std::io::Result<Option<Certificate>> {
        let addr = self.arguments.get_addr();
        let listener = TcpListener::bind(addr)?; // Привязка к адресу и порту

        self.init_dispatcher()?; // Инициализация диспетчера
        self.init_runners(self.arguments.get_concurrency())?; // Инициализация раннеров

        // Выполнить серверную публикацию слотов клиентам с предварительным индивидуальным шифрованием в зависимости от concurrency
        loop {
            if if let Ok(planned) = self.planned.lock() {
                planned.len() > 0
            } else {
                false
            } {
                if let Some(mut runner) = self.runners.lock().unwrap().pop_back() {
                    runner.run(self.planned.clone());
                } else {
                    // подождать освобождение раннера
                    sleep(std::time::Duration::from_millis(100));
                }
            } else {
                break;
            }
        }

        let listener = Arc::new(Mutex::new(listener));
        let server = Arc::new(Mutex::new(self.clone()));

        let connection_manager = spawn(move || -> std::io::Result<()> {
            // Основной цикл обработки входящих соединений
            if let Ok(listener) = listener.lock() {
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            if let Ok(server) = &mut server.lock() {
                                server.handle_stream(stream)?
                            }
                        }, // Обработка успешного соединения
                        Err(e) => {
                            crate::d(format!("Warning: TcpStream\tincoming error: {:#?}", e))
                        } // Обработка ошибок соединения
                    }
                }
            }
            Ok(())
        });

        let _thread = connection_manager.thread();

        let mut solution = None;

        loop {
            if let Ok(smpc_field) = &self.smpc_field.lock() {
                if smpc_field.is_points_loaded(self.config.get_public_keys().len() - 1) {
                    solution = smpc_field.get_solution(&self.keypair.get_secret_key());
                    if solution.is_some() {
                        break;
                    }
                }
            }
            sleep(std::time::Duration::from_millis(1000));
            crate::d(format!("Ожидание данных для вычисления результата."));
        }

        match solution {
            Some(solution) => Ok(solution),
            None => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Interrupted",
                ))
            }
        }
    }

    /// Инициализирует диспетчер и создает контекст для обработки запросов.
    fn init_dispatcher(&self) -> std::io::Result<()> {
        let context = WelsibContext::new(
            None,
            self.config.clone(),
            self.keypair.clone(),
            // self.channels.clone(),
            // self.resource.clone(),
            // self.has_executor_connected.clone(),
            self.smpc_field.clone(),
            self.runners.clone(),
            self.planned.clone(),
            // self.api_request_elapsed_time.clone(),
            // self.sender.clone(),
            // self.receiver.clone(),
            self.dispatcher.clone(),
            self.is_pub.clone()
        );

        // Блокировка диспетчера для обработки контекста
        match self.dispatcher.lock().as_deref_mut() {
            Ok(dispatcher) => {
                if let Err(e) = dispatcher.handle(context) {
                    crate::d(format!("Error: {:#?}", &e));
                }
            }
            Err(e) => {
                crate::d(format!("Error: {:#?}", &e));
            }, // Обработка ошибок блокировки
        }

        Ok(())
    }

    /// Инициализация раннеров (runner - отдельный параллельный процесс запускающий выполнение рассчётов calculation)
    fn init_runners(&self, count: usize) -> std::io::Result<()> {
        if count < 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Ошибка, раннеров должно быть не менее одного.",
            ));
        }
        for i in 0..count {
            if let Ok(mut runners) = self.runners.lock() {
                runners.push_front(Runner::new(self.runners.clone()));
            }
        }
        Ok(())
    }

    /// Обрабатывает входящее соединение (поток данных).
    fn handle_stream(&mut self, stream: std::net::TcpStream) -> std::io::Result<()> {
        // Установка таймаутов для чтения и записи
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;

        // Создание WelsibStream
        let welsib_stream = WelsibStream {
            tcp_stream: Some(stream)
        };

        // Если поток успешно создан, создаем контекст и передаем его диспетчеру
        let context = WelsibContext::new(
            Some(Arc::new(Mutex::new(welsib_stream))),
            self.config.clone(),
            self.keypair.clone(),
            // self.channels.clone(),
            // self.resource.clone(),
            // self.has_executor_connected.clone(),
            self.smpc_field.clone(),
            self.runners.clone(),
            self.planned.clone(),
            // self.api_request_elapsed_time.clone(),
            // self.sender.clone(),
            // self.receiver.clone(),
            self.dispatcher.clone(),
            self.is_pub.clone()
        );

        // Блокировка диспетчера для обработки контекста
        match self.dispatcher.lock().as_deref_mut() {
            Ok(dispatcher) => {
                if let Err(e) = dispatcher.handle(context) {
                    crate::d(format!("Error: {:#?}", &e));
                }
            }
            Err(e) => {
                crate::d(format!("Error: {:#?}", &e));
            }, // Обработка ошибок блокировки
        }

        Ok(())
    }
}