#/bin/bash

# Сгенерировать пароль для шифрования файла корневого ключа сервера-проверяющего (контролёра, аудитора)
cat /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | fold -w 34 | head -n 1 > .example-smpc-server-password.txt
# Сгенерировать зашифрованный файл с корневым ключём сервера-проверяющего (контролёра, аудитора)
cat ./.example-smpc-server-password.txt | ../../welsib-tools/target/release/welsib-make-key > smpc-server-example-key.pem

# Сгенерировать ключ для шифрования файла корневого ключа клиента-общей суммы
cat /dev/urandom | LC_ALL=C tr -dc 'A-Za-f0-9' | fold -w 34 | head -n 1 > .example-smpc-client-sum-password.txt
# Сгенерировать зашифрованный файл с корневым ключём клиента-общей суммы
cat ./.example-smpc-client-sum-password.txt | ../../welsib-tools/target/release/welsib-make-key > smpc-client-sum-example-key.pem

# Сгенерировать ключ для шифрования файла корневого ключа клиента-слагаемого 1
cat /dev/urandom | LC_ALL=C tr -dc 'A-Za-f0-9' | fold -w 34 | head -n 1 > .example-smpc-client-part1-password.txt
# Сгенерировать зашифрованный файл с корневым ключём клиента-слагаемого 1
cat ./.example-smpc-client-part1-password.txt | ../../welsib-tools/target/release/welsib-make-key > smpc-client-part1-example-key.pem

# Сгенерировать ключ для шифрования файла корневого ключа клиента-слагаемого 2
cat /dev/urandom | LC_ALL=C tr -dc 'A-Za-f0-9' | fold -w 34 | head -n 1 > .example-smpc-client-part2-password.txt
# Сгенерировать зашифрованный файл с корневым ключём клиента-слагаемого 2
cat ./.example-smpc-client-part2-password.txt | ../../welsib-tools/target/release/welsib-make-key > smpc-client-part2-example-key.pem

# Создание публичных ключей на основе секретных и генерация конфигурационного файла
cat ./.example-smpc-client-part1-password.txt | ../../welsib-tools/target/release/welsib-make-point smpc-client-part1-example-key.pem > smpc-client-part1-example-point.pem
cat ./.example-smpc-client-part2-password.txt | ../../welsib-tools/target/release/welsib-make-point smpc-client-part2-example-key.pem > smpc-client-part2-example-point.pem
cat ./.example-smpc-client-sum-password.txt | ../../welsib-tools/target/release/welsib-make-point smpc-client-sum-example-key.pem > smpc-client-sum-example-point.pem
cat ./.example-smpc-server-password.txt | ../../welsib-tools/target/release/welsib-make-point smpc-server-example-key.pem > smpc-server-example-point.pem

echo `pwd`"/smpc-client-part1-example-point.pem" > smpc.conf
echo `pwd`"/smpc-client-part2-example-point.pem" >> smpc.conf
echo `pwd`"/smpc-client-sum-example-point.pem" >> smpc.conf
echo `pwd`"/smpc-server-example-point.pem" >> smpc.conf

# Генерация файлов с значениями value для каждого клиента
echo "100" > value-client-sum.txt
echo "51" > value-client-part1.txt
echo "49" > value-client-part2.txt
# 100 = 51 + 49

# Шифрование текстовых файлов с значениями value
cat smpc-client-sum-example-point.pem | ../../welsib-tools/target/release/welsib-encrypt-file value-client-sum.txt
cat smpc-client-part1-example-point.pem | ../../welsib-tools/target/release/welsib-encrypt-file value-client-part1.txt
cat smpc-client-part2-example-point.pem | ../../welsib-tools/target/release/welsib-encrypt-file value-client-part2.txt

# welsib-make-key и welsib-make-point
# специальные не распространяемые приложения автора,
# выполняющие создание ключей в соответствии с фундаментальными основами криптографии на эллиптических кривых для 512 битных чисел и параметрами:
# p: d2e0661903a34c95e129c4ecda27ddca565b9d6f9e5e491815e00f97ff9a184cc206d007446c511dd3ba23564f04933ed9c7fa20c1c92587bffa2d9fe61e5183
# a: 3e89c5efa17401ed19c1f1920612e00a50bcca3e78bde4aae31e6a2dce72dface17061d71ef8a68313be0722be1308d608be5a064d656161bbd053b26b4db21e
# b: ce2bd16da835c9844c7fcf76629b12d23696dbb1dd8e4e86ae4d43753832c048616241ae921d0f4fc5decc12e47d77bd3b89157afa9f2a2b0fb7ba2794c01a44
# m: d2e0661903a34c95e129c4ecda27ddca565b9d6f9e5e491815e00f97ff9a184b83a2a757886b556a850e265be0137ba70353b16ffc288c5a54e2e9a6ac06f4cb
# q: d2e0661903a34c95e129c4ecda27ddca565b9d6f9e5e491815e00f97ff9a184b83a2a757886b556a850e265be0137ba70353b16ffc288c5a54e2e9a6ac06f4cb
# x: 6ba4b9411d837ff74469d77a7dc7b1fc02a3591865ad6d1670751e6adb6f7fcbb20acc66b3e9e43235889d7ba403ac4b462d7634a536126408b729da10d4f429
# y: a33c5b39011af91370c22e29e74cb00a7a4ea0990aea8facc56edae9f82bb4c7e559909ac1013a00e6e4e42f0fb0a1bdd514beb453786c5222152882987d8917
