#/bin/bash

# Сгенерировать ключ для шифрования файла корневого ключа сервера-проверяющего (контролёра, аудитора)
cat /dev/urandom | LC_ALL=C tr -dc 'a-f0-9' | fold -w 128 | head -n 1 > .example-smpc-server-gamma-key.txt
# Сгенерировать зашифрованный файл с корневым ключём сервера-проверяющего (контролёра, аудитора)
cat ./.example-smpc-server-gamma-key.txt | ../../esig-tools/target/release/make-root-key smpc-server-example.key

# Сгенерировать ключ для шифрования файла корневого ключа клиента-общей суммы
cat /dev/urandom | LC_ALL=C tr -dc 'a-f0-9' | fold -w 128 | head -n 1 > .example-smpc-client-sum-gamma-key.txt
# Сгенерировать зашифрованный файл с корневым ключём клиента-общей суммы
cat ./.example-smpc-client-sum-gamma-key.txt | ../../esig-tools/target/release/make-root-key smpc-client-sum-example.key

# Сгенерировать ключ для шифрования файла корневого ключа клиента-слагаемого 1
cat /dev/urandom | LC_ALL=C tr -dc 'a-f0-9' | fold -w 128 | head -n 1 > .example-smpc-client-part1-gamma-key.txt
# Сгенерировать зашифрованный файл с корневым ключём клиента-слагаемого 1
cat ./.example-smpc-client-part1-gamma-key.txt | ../../esig-tools/target/release/make-root-key smpc-client-part1-example.key

# Сгенерировать ключ для шифрования файла корневого ключа клиента-слагаемого 2
cat /dev/urandom | LC_ALL=C tr -dc 'a-f0-9' | fold -w 128 | head -n 1 > .example-smpc-client-part2-gamma-key.txt
# Сгенерировать зашифрованный файл с корневым ключём клиента-слагаемого 2
cat ./.example-smpc-client-part2-gamma-key.txt | ../../esig-tools/target/release/make-root-key smpc-client-part2-example.key

# Создание публичных ключей на основе секретных и генерация конфигурационного файла
cat ./.example-smpc-client-part1-gamma-key.txt | ../../esig-tools/target/release/welsib-make-pubkey --key=smpc-client-part1-example.key --print > smpc.conf
cat ./.example-smpc-client-part2-gamma-key.txt | ../../esig-tools/target/release/welsib-make-pubkey --key=smpc-client-part2-example.key --print >> smpc.conf
cat ./.example-smpc-client-sum-gamma-key.txt | ../../esig-tools/target/release/welsib-make-pubkey --key=smpc-client-sum-example.key --print >> smpc.conf
cat ./.example-smpc-server-gamma-key.txt | ../../esig-tools/target/release/welsib-make-pubkey --key=smpc-server-example.key --print >> smpc.conf


# make-root-key и welsib-make-pubkey
# специальные не распространяемые приложения автора,
# выполняющие создания ключей в соответствии с ГОСТ 34.10-2018 и
# OID: 1.2.643.7.1.2.1.2.1, TC26: id-tc26-gost-3410-12-512-paramSetA


