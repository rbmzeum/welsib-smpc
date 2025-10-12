#!/bin/bash

# Скрипт запуска сервера-контролёра для SMPC
# Сервер проверяет выполнение выражения X1 + X2 + ... + Xk == Y

echo "Запуск сервера-контролёра..."

if [ ! -f "secrets/smpc-server-password.txt" ]; then
    echo "Ошибка: ключ сервера не найден"
    exit 1
fi

cat secrets/smpc-server-password.txt | \
./bin/welsib-smpc-server \
    --key=keys/private/smpc-server-key.pem \
    --config=smpc.conf \
    --concurrency=4 > certificate.txt

echo "Сертификат сохранен в certificate.txt"
