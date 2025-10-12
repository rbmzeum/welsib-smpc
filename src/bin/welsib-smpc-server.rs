use welsib_smpc::{certificate, server::print_help::print_help};
use welsib_smpc::server::arguments::WelsibServerArguments;
use welsib_smpc::server::Server;
use welsib_smpc::helpers::pipe_gamma_key::StdInGammaKeyArguments;
use welsib_smpc::helpers::arg_key::Keypair;
use welsib_smpc::helpers::arg_conf::Config;
use std::sync::{Arc, Mutex};
use welsib_tools::tools::keys::password_input::WelsibKeysPasswordInput;
use welsib_tools::tools::base64::{base64_encode, base64_decode};
use welsib_u512_ec::hash::whash;

fn main() -> std::io::Result<()> {
    // TODO: server & middle & verifier
    // 1. Запускается сервис доступный через TCP-IP с конфигурацией передаваемой через пайп
    // 2. После подключения всех участников срабатывает транзакция из последовательностей взаимодействий участников
    // 3. В результате вычисляются две точки на эллиптической кривой разными способами и сравниваются
    // 4. Если точки (x координаты) равны, то сумма частей совпадает с результатом (с учётом округления или без)
    // 5. В успешном случае выдаётся 1, в случае не совпадения выдаётся 0

    // Init
    let arguments = WelsibServerArguments::init();
    if arguments.need_help() {
        print_help();
        return Ok(());
    }
    welsib_smpc::d(format!("Arguments: {:#?}", &arguments));

    let stdin = WelsibKeysPasswordInput::read()?;

    let keypair = Keypair::encode(arguments.get_secret_key_filename()?, stdin.input)?;

    let config = Config::read(arguments.get_config_filename()?)?;
    welsib_smpc::d(format!("Config: {:#?}", &config));

    // Run
    let mut server = Server::new(&config, &arguments, keypair)?;
    let certificate = server.run()?;

    // Done
    if let Some(certificate) = certificate {
        println!("{}", certificate.to_string());
    }
    Ok(())
}