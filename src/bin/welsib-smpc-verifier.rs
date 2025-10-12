use welsib_smpc::helpers::arg_conf::Config;
use welsib_smpc::verifier::print_help::print_help;
use welsib_smpc::verifier::arguments::WelsibVerifierArguments;
use welsib_smpc::helpers::pipe_certificate::StdInCertificate;
use welsib_smpc::verifier::Verifier;

// Верификация сертификата созданного SMPC сервером
fn main() -> std::io::Result<()> {
    // Init
    let arguments = WelsibVerifierArguments::init();
    if arguments.need_help() {
        print_help();
        return Ok(());
    }
    // println!("Arguments: {:#?}", &arguments);

    let stdin_certificate = StdInCertificate::read()?;
    // println!("Certificate: {:#?}", &stdin_certificate);

    let config = Config::read(arguments.get_config_filename()?)?;
    // println!("Config: {:#?}", &config);

    // Run
    let mut verifier = Verifier::new(&config, &stdin_certificate)?;
    let is_verified = verifier.run()?;

    // Done
    if let (is_verified_matrix_agg_points, is_verified_list_agg_points, is_verified_agg_point_hash, is_verified_signature) = is_verified {
        println!("matrix_points_agg == agg_point: {}", if is_verified_matrix_agg_points {"true"} else {"false"});
        println!("list_points_agg == agg_point: {}", if is_verified_list_agg_points {"true"} else {"false"});
        println!("hash(agg_point) == agg_point_hash: {}", if is_verified_agg_point_hash {"true"} else {"false"});
        println!("signature verified: {}", if is_verified_signature {"true"} else {"false"});
    }

    Ok(())
}
