#!/bin/bash

# Скрипт запуска клиента-участника для SMPC
# Использование: ./run-client.sh <value> [--sum]
#   <value> - числовое значение участника (0-100)
#   --sum   - флаг, указывающий что это клиент суммы (Y)

if [ $# -lt 1 ]; then
    echo "Использование: $0 <value> [--sum]"
    echo "  <value> - числовое значение участника (0-100)"
    echo "  --sum   - если указан, запускает клиент суммы"
    exit 1
fi

VALUE=$1
IS_SUM=false

if [ $# -eq 2 ] && [ "$2" = "--sum" ]; then
    IS_SUM=true
fi

if [ ! -f "secrets/smpc-client-value${VALUE}-password.txt" ]; then
    echo "Ошибка: ключ для значения $VALUE не найден"
    exit 1
fi

if [ "$IS_SUM" = true ]; then
    # Запуск клиента суммы
    echo "Запуск клиента суммы (Y) со значением $VALUE"
    cat "secrets/smpc-client-value${VALUE}-password.txt" | \
    ./bin/welsib-smpc-client \
        --key="keys/private/smpc-client-value${VALUE}-key.pem" \
        --config=smpc.conf \
        --concurrency=4 \
        --value="values/encrypted/value-client-value${VALUE}.txt.aggc" \
        --sum > "result-sum-${VALUE}.txt"
    echo "Результат клиента суммы сохранен в result-sum-${VALUE}.txt"
else
    # Запуск клиента части
    echo "Запуск клиента части (X) со значением $VALUE"
    cat "secrets/smpc-client-value${VALUE}-password.txt" | \
    ./bin/welsib-smpc-client \
        --key="keys/private/smpc-client-value${VALUE}-key.pem" \
        --config=smpc.conf \
        --concurrency=4 \
        --value="values/encrypted/value-client-value${VALUE}.txt.aggc" > "result-part-${VALUE}.txt"
    echo "Результат клиента части сохранен в result-part-${VALUE}.txt"
fi
