#!/bin/bash

# Скрипт генерации демонстрационной конфигурации SMPC
# Выбирает случайные значения так, чтобы их сумма равнялась другому значению из диапазона

set -e

# Параметры
MIN_PARTIES=2    # Минимальное количество участников
MAX_PARTIES=5    # Максимальное количество участников
MAX_ATTEMPTS=100 # Максимальное количество попыток подбора

echo "Генерация демонстрационной конфигурации..."

# Случайное количество участников
NUM_PARTIES=$(( RANDOM % (MAX_PARTIES - MIN_PARTIES + 1) + MIN_PARTIES ))

echo "Выбор $NUM_PARTIES участников..."

# Функция для поиска валидной комбинации
find_valid_combination() {
    local attempts=0
    while [ $attempts -lt $MAX_ATTEMPTS ]; do
        # Выбираем случайные значения для участников
        local sum=0
        local values=()
        local used_values=""  # Строка для отслеживания использованных значений
        
        for ((i=0; i<NUM_PARTIES; i++)); do
            while true; do
                local val=$(( RANDOM % 51 + 1 ))  # Значения от 1 до 51
                # Проверяем, что значение еще не использовалось
                if [[ ! " $used_values " =~ " $val " ]]; then
                    values[$i]=$val
                    used_values="$used_values $val"
                    sum=$((sum + val))
                    break
                fi
            done
        done
        
        # Проверяем, что сумма в допустимом диапазоне и не использовалась
        if [ $sum -le 100 ] && [[ ! " $used_values " =~ " $sum " ]]; then
            echo "${values[@]} $sum"
            return 0
        fi
        
        attempts=$((attempts + 1))
    done
    
    # Если не нашли комбинацию, используем детерминированную
    echo "1 2 3 6"  # 1+2+3=6
    return 0
}

# Получаем валидную комбинацию
result=($(find_valid_combination))
VALUES=("${result[@]}")
SUM_VALUE=${VALUES[-1]}
unset 'VALUES[${#VALUES[@]}-1]'

echo "Сгенерированные значения: ${VALUES[*]}"
echo "Сумма: $SUM_VALUE"

# Создание конфигурационного файла
echo "Создание конфигурационного файла..."
> smpc.conf

# Пути к публичным ключам участников (частей суммы)
for value in "${VALUES[@]}"; do
    echo "$(pwd)/keys/public/smpc-client-value${value}-point.pem" >> smpc.conf
done

# Путь к публичному ключу суммы
echo "$(pwd)/keys/public/smpc-client-value${SUM_VALUE}-point.pem" >> smpc.conf

# Путь к публичному ключу сервера (последняя строка)
echo "$(pwd)/keys/public/smpc-server-point.pem" >> smpc.conf

# Сохранение информации о демо (исправленная версия)
> demo-info.txt
echo "NUM_PARTIES=$NUM_PARTIES" >> demo-info.txt
# Сохраняем значения в виде массива для безопасного чтения
echo "PART_VALUES=(${VALUES[*]})" >> demo-info.txt
echo "SUM_VALUE=$SUM_VALUE" >> demo-info.txt

echo "Демонстрационная конфигурация успешно сгенерирована!"
echo "Участники (Xi): ${VALUES[*]}"
echo "Сумма (Y): $SUM_VALUE"
echo "Проверка: $(IFS=+; echo "${VALUES[*]}") = $SUM_VALUE"
echo "Конфигурационный файл: $(pwd)/smpc.conf"
