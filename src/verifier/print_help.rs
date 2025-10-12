pub fn print_help() {
    println!("welsib-smpc-verifier -- верификатор сертификата созданного сервером многосторонней верификации выражения без разглашения слагаемых и результирующей суммы [версия 0.1.0.0]"); // major, minor, patch, build number
    // TODO: если --value не указан, то value считается равным нулю
    println!(
        "\n\
        Использование:\techo \"<cetrificate>\" | welsib-smpc-verifier --config=smpc.conf\n\
        \t-h, --help\t\tсправка\n\
        \t--config=[CONFIG_FILENAME]\t\tимя файла со списком публичных ключей клиентов\n\
        \twelsib-smpc-verifier -- Верификатор сертификата созданного сервером многосторонних конфеденциальных вычислений\n\
        \tSecure Multi-Party Computation (SMPC)\n\n\
        Формат конфигурационного файла:\n\
        \tв каждой строке публичный ключ участника, в предпоследней строке ключ владельца суммы,\n\
        \tв последней ключ сервера (контролёра)\n\n\
        Использование:\n\
        \techo \"<cetrificate>\" | welsib-smpc-verifier --config=smpc.conf\n\
        \tcat ./certificate.txt | ../target/release/welsib-smpc-verifier --config=smpc.conf\n\n\
        "
    );
}
