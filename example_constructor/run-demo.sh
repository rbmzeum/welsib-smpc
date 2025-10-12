#!/bin/bash

# Скрипт запуска полной демонстрации SMPC
# Запускает всех участников и сервер согласно demo-info.txt

set -e

if [ ! -f "demo-info.txt" ]; then
    echo "Ошибка: файл demo-info.txt не найден. Сначала выполните generate-demo.sh"
    exit 1
fi

echo "Загрузка параметров демо..."

# Безопасное чтение demo-info.txt
NUM_PARTIES=$(grep "^NUM_PARTIES=" demo-info.txt | cut -d'=' -f2)
SUM_VALUE=$(grep "^SUM_VALUE=" demo-info.txt | cut -d'=' -f2)

# Чтение массива значений безопасным способом
PART_VALUES_STR=$(grep "^PART_VALUES=" demo-info.txt | cut -d'=' -f2 | tr -d '()')
PART_VALUES=($PART_VALUES_STR)

echo "Запуск демонстрации SMPC"
echo "Участники: ${PART_VALUES[*]}"
echo "Сумма: $SUM_VALUE"
echo ""

# Проверка существования необходимых файлов
for value in "${PART_VALUES[@]}"; do
    if [ ! -f "secrets/smpc-client-value${value}-password.txt" ]; then
        echo "Ошибка: ключ для значения $value не найден"
        exit 1
    fi
    if [ ! -f "values/encrypted/value-client-value${value}.txt.aggc" ]; then
        echo "Ошибка: зашифрованное значение для $value не найдено"
        exit 1
    fi
done

if [ ! -f "secrets/smpc-client-value${SUM_VALUE}-password.txt" ]; then
    echo "Ошибка: ключ для суммы $SUM_VALUE не найден"
    exit 1
fi

# Запуск клиентов-участников (Xi)
echo "Запуск клиентов-участников..."
declare -A CLIENT_PIDS

for value in "${PART_VALUES[@]}"; do
    echo "Запуск клиента со значением $value (Xi)"
    ./run-client.sh $value &
    CLIENT_PIDS[$value]=$!
    sleep 1
done

# Запуск клиента суммы (Y)
echo "Запуск клиента суммы со значением $SUM_VALUE (Y)"
./run-client.sh $SUM_VALUE --sum &
SUM_PID=$!
sleep 1

# Запуск сервера
echo "Запуск сервера-контролёра..."
./run-server.sh &
SERVER_PID=$!

# Ожидание завершения
echo ""
echo "Ожидание завершения процессов..."

# Ожидаем завершения сервера в первую очередь
wait $SERVER_PID 2>/dev/null || true
echo "Сервер завершил работу"

# Ожидаем завершения клиента суммы
wait $SUM_PID 2>/dev/null || true
echo "Клиент суммы завершил работу"

# Ожидаем завершения клиентов-участников
for value in "${PART_VALUES[@]}"; do
    if [ -n "${CLIENT_PIDS[$value]}" ]; then
        wait ${CLIENT_PIDS[$value]} 2>/dev/null || true
        echo "Клиент $value завершил работу"
    fi
done

echo ""
echo "Демонстрация завершена!"
echo "Результаты сохранены в result-*.txt и certificate.txt"
