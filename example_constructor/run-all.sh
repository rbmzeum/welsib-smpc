#!/bin/bash

# Скрипт запуска всех участников и сервера
# Запускает всех клиентов-участников и сервер для проверки выражения

NUM_PARTIES=5  # Должно соответствовать значению в generate-demo.sh

echo "Запуск всех $NUM_PARTIES участников..."

# Запуск клиентов-частей
for ((i=0; i<NUM_PARTIES; i++)); do
    echo "Запуск клиента $i..."
    ./run-client.sh $i &
    CLIENT_PIDS[$i]=$!
done

# Короткая пауза для запуска клиентов
sleep 2

# Запуск сервера
echo "Запуск сервера..."
./run-server.sh &
SERVER_PID=$!

# Ожидание завершения
echo "Ожидание завершения процессов..."
for ((i=0; i<NUM_PARTIES; i++)); do
    wait ${CLIENT_PIDS[$i]}
    echo "Клиент $i завершен"
done

wait $SERVER_PID
echo "Сервер завершен"

echo "Все процессы завершены. Проверьте результаты в файлах result-*.txt и certificate.txt"
