#!/bin/bash

# Скрипт генерации полного диапазона ключей для SMPC (0-100)
# Генерирует ключи для всех значений от 0 до 100

set -e

# Создание директорий
mkdir -p secrets keys/private keys/public values/plain values/encrypted

echo "Генерация полного диапазона ключей для значений 0-100..."

# Генерация ключей и паролей для сервера-проверяющего
echo "Генерация ключей сервера..."
cat /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | fold -w 34 | head -n 1 > secrets/smpc-server-password.txt
cat secrets/smpc-server-password.txt | ../../welsib-tools/target/release/welsib-make-key > keys/private/smpc-server-key.pem
cat secrets/smpc-server-password.txt | ../../welsib-tools/target/release/welsib-make-point keys/private/smpc-server-key.pem > keys/public/smpc-server-point.pem

# Генерация ключей для всех значений от 0 до 100
for i in {0..100}; do
    echo "Генерация ключей для значения $i..."
    
    # Генерация пароля
    cat /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | fold -w 34 | head -n 1 > "secrets/smpc-client-value${i}-password.txt"
    
    # Генерация приватного ключа
    cat "secrets/smpc-client-value${i}-password.txt" | ../../welsib-tools/target/release/welsib-make-key > "keys/private/smpc-client-value${i}-key.pem"
    
    # Генерация публичного ключа
    cat "secrets/smpc-client-value${i}-password.txt" | ../../welsib-tools/target/release/welsib-make-point "keys/private/smpc-client-value${i}-key.pem" > "keys/public/smpc-client-value${i}-point.pem"
    
    # Создание файла со значением
    echo "$i" > "values/plain/value-client-value${i}.txt"
    
    # Шифрование значения
    if [ -f "values/plain/value-client-value${i}.txt" ]; then
        cat "keys/public/smpc-client-value${i}-point.pem" | ../../welsib-tools/target/release/welsib-encrypt-file "values/plain/value-client-value${i}.txt"
        if [ -f "values/plain/value-client-value${i}.txt.aggc" ]; then
            mv "values/plain/value-client-value${i}.txt.aggc" "values/encrypted/"
        fi
    fi
done

echo "Генерация полного диапазона ключей завершена!"
