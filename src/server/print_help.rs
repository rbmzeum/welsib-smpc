pub fn print_help() {
    println!("welsib-smpc-server -- сервер многосторонней верификации выражения без разглашения слагаемых и результирующей суммы [версия 0.1.0.0]"); // major, minor, patch, build number
    // println!(
    //     "\n\
    //     Использование:\techo \"<gamma-key>\" | welsib-smpc-server --key=smpc-server.key --config=smpc.conf --concurrency=4\n\
    //     \t-h, --help\t\tсправка\n\
    //     \t--key=[KEY_FILENAME]\t\tимя файла секретного ключа\n\
    //     \t--config=[CONFIG_FILENAME]\t\tимя файла со списком публичных ключей клиентов\n\
    //     \t--host=[HOST]\t\tиспользовать доменное имя или ip отличный от 127.0.0.1\n\
    //     \t--port=[PORT]\t\tиспользовать порт из диапазона 1024..65535 (по умолчанию 8555)\n\
    //     \t--concurrency=[N]\t\tмаксимальное число параллельных вычислительных процессов\n\
    //     \twelsib-smpc-server -- Secure Multi-Party Computation (SMPC) сервер позволяет удостовериться в корректности выражения\n\
    //     \tчлены которого распределны между разными участниками и не разглашаются\n\n\
    //     Формат конфигурационного файла:\n\
    //     \tв каждой строке публичный ключ участника, в предпоследней строке ключ владельца суммы, в последней ключ сервера (контролёра)\n\
    //     \tконфигурационный файл для всех участников одинаковый и с одинаковым порядком расположения ключей\n\n\
    //     Использование:\n\
    //     \techo \"<gamma-key>\" | welsib-smpc-server --key=control.key --config=welsib-smpc-client-keys.json\n\
    //     \tcat ./.example-smpc-server-gamma-key.txt | ../target/release/welsib-smpc-server --key=smpc-server-example.key --config=smpc.conf --pub\n\
    //     \tcat /root/secure_ramdisk/.gamma-key.txt | welsib-smpc-server --key=smpc-server-example.key --config=smpc.conf --host=192.168.2.2 --port=8555 --concurrency=4\n\
    //     cat ./.example-smpc-server-gamma-key.txt | ../target/release/welsib-smpc-server --key=smpc-server-example.key --config=smpc.conf --pub --concurrency=4
    //     "
    // );

    // Основное использование
    println!("\n\x1b[1;33mИСПОЛЬЗОВАНИЕ:\x1b[0m");
    println!("  \x1b[1mwelsib-smpc-server\x1b[0m [\x1b[36mОПЦИИ\x1b[0m]");

    // Опции
    println!("\n\x1b[1;33mОПЦИИ:\x1b[0m");
    println!("  \x1b[32m-h, --help\x1b[0m              Показать эту справку и выйти");
    println!("  \x1b[32m-v, --version\x1b[0m           Показать информацию о версии");
    println!("  \x1b[32m--key=<ФАЙЛ>\x1b[0m            PEM файл ключа");
    println!("  \x1b[32m--config=<ФАЙЛ>\x1b[0m         Конфигурационный файл");
    println!("  \x1b[32m--concurrency=<ЧИСЛО>\x1b[0m   Число параллельных процессов");
    println!("  \x1b[32m--host=<IP>\x1b[0m             IP адрес хоста");
    println!("  \x1b[32m--port=<PORT>\x1b[0m           Номер порта (по умолчанию 8555)");

    // Примеры
    println!("\n\x1b[1;33mПРИМЕРЫ ИСПОЛЬЗОВАНИЯ:\x1b[0m");

    println!(
        "\n\
        \tcat .example-smpc-server-password.txt | welsib-smpc-server --key=smpc-server-example-key.pem --config=smpc.conf --concurrency=4 > certificate.txt\n\
        "
    );
}

/*
Пример конфига:
{"x":"70d04251ecd96fbff46c70265bd2c747637c2863c98faed527f3f53bf1d0efe14ab9beb2e3c31da8699f37e1cbb0a3224be426d7f5e7af6b01d8436d6ed98b2f","y":"0b70cf7252f026cba23973476052924c1f19d925dd9d5ef4ee6783043a6a1ef76a231629ad55246b3c569825da0b9f4b4251fa466f657706d3ba442fa630fc44"}
{"x":"7112eab20de02be6d3b8c45c63ade8b1d4b9eb41e88e18caac5f8fd17743de85ca98b7ba2621129a2fbafc1ce8b2283eb8bc2f57da83bcf73ab43206a8d4605c","y":"a7eeffeddfbbd1d5caea644f0baf3076269935f0aeff24a1af71d46c91a900c49445db12e87be024c067a1e620d3e20cb18e8eb91ee2a2e10561e1d1fd2410bc"}
{"x":"c7f3a912ec2e27060b30d5ea5598468e5d51d62c8923835c6d50fa22eedbeb207d9deec4b51505d03205f4a8f1fd4e956b60ce02f4ccd68d3d9840487e5dba3f","y":"481c49f7a4137a6b11a465fec33e409c2ba55de56127cd76654f48a99782b1f1df3631682280e884ddff86eb4f9443a89d6f30fd43ba7d8dd35610e61850f5c7"}
{"x":"151ef888ba8315af77c4751cdc43c965459f8dd623e9da1b7d422918d1784eefd1c9196499e41b69b17f0b35c8a993e266ec0df897b28f8396adc04069f3be3e","y":"2c68847485ec64181df59242d794d45b4cc4ac643c5eadcdc6d8a712e0629351d31a1c868bfab5c147d1dbd53f309b7915f2b7788b85b2a45c1af7d7f943e88b"}
*/