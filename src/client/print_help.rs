pub fn print_help() {
    println!("welsib-smpc-client -- клиент многосторонней верификации выражения без разглашения слагаемых и результирующей суммы [версия 0.1.0.0]"); // major, minor, patch, build number
    // TODO: если --value не указан, то value считается равным нулю
    // println!(
    //     "\n\
    //     Использование:\techo \"<gamma-key>\" | welsib-smpc-client --key=smpc-client.key --config=smpc.conf --sum --concurrency=4 --value=100\n\
    //     \t-h, --help\t\tсправка\n\
    //     \t--key=[KEY_FILENAME]\t\tимя файла секретного ключа\n\
    //     \t--config=[CONFIG_FILENAME]\t\tимя файла со списком публичных ключей клиентов\n\
    //     \t--host=[HOST]\t\tиспользовать доменное имя или ip отличный от 127.0.0.1\n\
    //     \t--port=[PORT]\t\tиспользовать порт из диапазона 1024..65535 (по умолчанию 8555)\n\
    //     \t--concurrency=[N]\t\tмаксимальное число параллельных вычислительных процессов\n\
    //     \t--value=[u64]\t\tисходное секретное значение, являющееся частью проверяемого выражения\n\
    //     \twelsib-smpc-client -- Secure Multi-Party Computation (SMPC) клиент позволяет удостовериться в корректности выражения\n\
    //     \tчлены которого распределны между разными участниками и не разглашаются\n\n\
    //     Формат конфигурационного файла:\n\
    //     \tв каждой строке публичный ключ участника, в предпоследней строке ключ владельца суммы, в последней ключ сервера (контролёра)\n\
    //     \tконфигурационный файл для всех участников одинаковый и с одинаковым порядком расположения ключей\n\n\
    //     Использование:\n\
    //     \techo \"<gamma-key>\" | welsib-smpc-client --key=control.key --config=smpc.conf\n\
    //     \tcat ./.example-smpc-client-gamma-key.txt | ../target/release/welsib-smpc-client --key=smpc-client-example.key --config=smpc.conf --value=10000\n\
    //     \tcat /root/secure_ramdisk/.gamma-key.txt | welsib-smpc-client --key=smpc-client-example.key --config=smpc.conf --host=192.168.2.2 --port=8555 --concurrency=4 --value=44\n\
    //     \tcat ./.example-smpc-client-sum-gamma-key.txt | ../target/release/welsib-smpc-client --key=smpc-client-sum-example.key --config=smpc.conf --sum --concurrency=4 --value=100\n\
    //     \tcat ./.example-smpc-client-part1-gamma-key.txt | ../target/release/welsib-smpc-client --key=smpc-client-part1-example.key --config=smpc.conf --concurrency=4 --value=55\n\
    //     \tcat ./.example-smpc-client-part2-gamma-key.txt | ../target/release/welsib-smpc-client --key=smpc-client-part2-example.key --config=smpc.conf --concurrency=4 --value=45\n\
    //     "
    // );

    // Основное использование
    println!("\n\x1b[1;33mИСПОЛЬЗОВАНИЕ:\x1b[0m");
    println!("  \x1b[1mwelsib-smpc-client\x1b[0m [\x1b[36mОПЦИИ\x1b[0m]");

    // Опции
    println!("\n\x1b[1;33mОПЦИИ:\x1b[0m");
    println!("  \x1b[32m-h, --help\x1b[0m              Показать эту справку и выйти");
    println!("  \x1b[32m-v, --version\x1b[0m           Показать информацию о версии");
    println!("  \x1b[32m--key=<ФАЙЛ>\x1b[0m            PEM файл ключа");
    println!("  \x1b[32m--config=<ФАЙЛ>\x1b[0m         Конфигурационный файл");
    println!("  \x1b[32m--concurrency=<ЧИСЛО>\x1b[0m   Число параллельных процессов");
    println!("  \x1b[32m--value=<ФАЙЛ>\x1b[0m          Шифрованный файл хранящий конфиденциальное значение в текстовом формате");
    println!("  \x1b[32m--host=<IP>\x1b[0m             IP адрес хоста");
    println!("  \x1b[32m--port=<PORT>\x1b[0m           Номер порта (по умолчанию 8555)");
    println!("  \x1b[32m--sum\x1b[0m                  Роль клиента: сумма с указанием --sum или слагаемое без указания --sum");

    // Примеры
    println!("\n\x1b[1;33mПРИМЕРЫ ИСПОЛЬЗОВАНИЯ:\x1b[0m");

    println!(
        "\n\
        \tcat .example-smpc-client-part1-password.txt | welsib-smpc-client --key=smpc-client-part1-example-key.pem --config=smpc.conf --concurrency=4 --value=value-client-part1.txt.aggc\n\
        \tcat .example-smpc-client-part2-password.txt | welsib-smpc-client --key=smpc-client-part2-example-key.pem --config=smpc.conf --concurrency=4 --value=value-client-part2.txt.aggc\n\
        \tcat .example-smpc-client-sum-password.txt | welsib-smpc-client --key=smpc-client-sum-example-key.pem --config=smpc.conf --concurrency=4 --value=value-client-sum.txt.aggc\n\
        "
    );
}

/*
cat .example-smpc-client-part1-password.txt | welsib-smpc-client --key smpc-client-part1-example-key.pem --config smpc.conf --concurrency 4 --value value-client-part1.txt.aggc
cat .example-smpc-client-part2-password.txt | welsib-smpc-client --key smpc-client-part2-example-key.pem --config smpc.conf --concurrency 4 --value value-client-part2.txt.aggc
cat .example-smpc-client-sum-password.txt | welsib-smpc-client --key smpc-client-sum-example-key.pem --config smpc.conf --concurrency 4 --value value-client-sum.txt.aggc
*/