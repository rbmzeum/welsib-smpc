// use welsib_smpc::helpers::pipe_gamma_key::StdInGammaKeyArguments;
use welsib_smpc::helpers::arg_key::Keypair;
use welsib_smpc::helpers::arg_conf::Config;
use welsib_smpc::client::print_help::print_help;
use welsib_smpc::client::arguments::WelsibClientArguments;
use welsib_smpc::client::Client;
use welsib_smpc::conv::u2vec::u2vec;
use welsib_tools::tools::keys::password_input::WelsibKeysPasswordInput;
use welsib_tools::tools::base64::{base64_encode, base64_decode};
use welsib_u512_ec::hash::whash;

fn main() -> std::io::Result<()> {
    // Init
    let arguments = WelsibClientArguments::init();
    if arguments.need_help() {
        print_help();
        return Ok(());
    }
    welsib_smpc::d(format!("Arguments: {:#?}", &arguments));

    let stdin = WelsibKeysPasswordInput::read()?;

    let keypair = Keypair::encode(arguments.get_secret_key_filename()?, stdin.input)?;
    // welsib_smpc::dd(format!("Keypair: {:x?}", &keypair), "keypair");

    let config = Config::read(arguments.get_config_filename()?)?;
    welsib_smpc::d(format!("Config: {:#?}", &config));

    // Run
    let mut client = Client::new(&config, &arguments, keypair)?;
    let (solution_point_matrix, solution_point_list) = client.run()?;

    // Done
    let x = u2vec(solution_point_matrix.x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let y = u2vec(solution_point_matrix.y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let solution_point_matrix_json = String::from(format!("{{\"x\":\"{x}\",\"y\":\"{y}\"}}"));
    let x = u2vec(solution_point_list.x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let y = u2vec(solution_point_list.y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let solution_point_list_json = String::from(format!("{{\"x\":\"{x}\",\"y\":\"{y}\"}}"));
    println!("{solution_point_matrix_json}\n{solution_point_list_json}");
    Ok(())
}