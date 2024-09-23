#!/bin/bash

# Включаем строгий режим
set -euo pipefail

# Переменные
LOG_DIR="/etc/amnezia/amneziawg/logs"
CONFIG_BASE_DIR="/etc/amnezia/amneziawg"
LOG_FILE="${LOG_DIR}/$(date +'%d.%m.%Y').log"

# Функция для логирования
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Функция для очистки в случае ошибки
cleanup() {
    if [[ -d "${CONFIG_DIR:-}" ]]; then
        echo "Произошла ошибка. Удаление созданной директории ${CONFIG_DIR}..."
        rm -rf "$CONFIG_DIR"
        echo "Директория ${CONFIG_DIR} удалена."
        log "Директория ${CONFIG_DIR} удалена из-за ошибки."
    fi
    # Опционально: удаление пустых директорий логов
    if [[ -d "$LOG_DIR" && -z "$(ls -A "$LOG_DIR")" ]]; then
        echo "Удаление пустой директории логов ${LOG_DIR}..."
        rmdir "$LOG_DIR"
        echo "Директория логов удалена."
        log "Пустая директория логов ${LOG_DIR} удалена."
    fi
}

# Устанавливаем ловушку для очистки при выходе с ошибкой
trap 'cleanup' EXIT

# Функция для проверки наличия необходимых команд
check_commands() {
    local missing=()
    for cmd in "$@"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "\e[31mОтсутствуют необходимые команды: ${missing[*]}. Пожалуйста, установите их перед запуском этого скрипта.\e[0m"
        log "Отсутствуют команды: ${missing[*]}"
        exit 1
    fi
}

# Функция для проверки валидности IP/подсети
is_valid_cidr() {
    local cidr=$1
    if [[ $cidr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
        # Дополнительная проверка на корректность чисел
        IFS='/' read -r ip mask <<< "$cidr"
        for octet in $(echo "$ip" | tr '.' ' '); do
            if (( octet < 0 || octet > 255 )); then
                return 1
            fi
        done
        if (( mask < 0 || mask > 32 )); then
            return 1
        fi
        return 0
    else
        return 1
    fi
}

# Генерация правил iptables на основе allowed_ips
generate_iptables_rules() {
    local interface_name=$1
    local client_ip=$2
    local allowed_ips=("${@:3}")  # Массив разрешенных IP

    iptables_rules_up=""
    iptables_rules_down=""

    # Проверяем, если первый элемент массива равен "0.0.0.0/0"
    if [[ "${allowed_ips[0]}" == "0.0.0.0/0" ]]; then
        log "Разрешён весь трафик. Дополнительные правила iptables не требуются."
    else
        log "Создание правил iptables для ограничения доступа к указанным IP-адресам."

        # Разрешаем установленный и связанный трафик
        iptables_rules_up+="PostUp = iptables -A FORWARD -i $interface_name -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
        iptables_rules_down+="PostDown = iptables -D FORWARD -i $interface_name -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"

        # Разрешаем трафик к разрешённым IP-адресам
        for ip in "${allowed_ips[@]}"; do
            iptables_rules_up+="PostUp = iptables -A FORWARD -i $interface_name -s $client_ip -d $ip -j ACCEPT\n"
            iptables_rules_down+="PostDown = iptables -D FORWARD -i $interface_name -s $client_ip -d $ip -j ACCEPT\n"
        done

        # Блокируем остальной трафик
        iptables_rules_up+="PostUp = iptables -A FORWARD -i $interface_name -s $client_ip -j DROP\n"
        iptables_rules_down+="PostDown = iptables -D FORWARD -i $interface_name -s $client_ip -j DROP\n"
    fi

    echo -e "$iptables_rules_up"
    echo -e "$iptables_rules_down"
}

# Функция для проверки доступности порта
is_port_available() {
    local port=$1
    if ss -tuln | grep -q ":${port} "; then
        return 1
    else
        return 0
    fi
}

# Проверка на выполнение с правами root
if [[ "${EUID}" -ne 0 ]]; then
   echo -e "\e[31mЭтот скрипт должен быть запущен с правами root\e[0m"
   log "Скрипт запущен не с правами root."
   exit 1
fi

# Проверка наличия необходимых команд
REQUIRED_COMMANDS=("awg" "curl" "ip" "shuf" "ss" "grep" "awk" "tee" "chmod" "rm" "mkdir" "rmdir" "systemctl")
check_commands "${REQUIRED_COMMANDS[@]}"

# Создаем директорию логов один раз
if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR" || { echo "Ошибка создания директории логов"; log "Ошибка создания директории логов"; exit 1; }
    log "Создана директория логов: $LOG_DIR"
fi

# Инициализируем файл логов
touch "$LOG_FILE" || { echo "Не удалось создать файл логов"; log "Не удалось создать файл логов"; exit 1; }
log "Начато создание конфигурации."

# Запрашиваем имя конфигурации и хост с валидацией
while true; do
    read -p "Введите имя конфигурации: " config_name
    if [[ "$config_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        log "Выбрано имя конфигурации: $config_name"
        break
    else
        echo "Имя конфигурации может содержать только буквы, цифры, тире и подчеркивания."
    fi
done

while true; do
    read -p "Введите хост (домен или IP): " host
    if [[ "$host" =~ ^([a-zA-Z0-9_-]+\.)*[a-zA-Z0-9_-]+\.[a-zA-Z]{2,}$ || "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        log "Выбран хост: $host"
        break
    else
        echo "Неверный формат хоста. Введите действительный домен или IP-адрес."
    fi
done

# Показать текущие порты Amnezia WG (если есть)
existing_ports=$(awg show all listen-port 2>/dev/null || echo "Нет активных портов.")
echo "Текущие порты Amnezia WG (если есть):"
echo "$existing_ports"
log "Текущие активные порты: $existing_ports"

# Запрашиваем порт после показа занятых портов с проверкой доступности
while true; do
    read -p "Введите порт для новой конфигурации (или оставьте пустым для рандомного выбора): " port
    if [[ -z "$port" ]]; then
        port=$(shuf -i 1000-52030 -n 1)
        echo "Выбран случайный порт: $port"
        log "Сгенерирован случайный порт: $port"
        break
    elif [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
        if is_port_available "$port"; then
            echo "Выбран порт: $port"
            log "Выбран порт: $port"
            break
        else
            echo "Порт $port уже используется. Выберите другой порт."
            log "Порт $port уже занят."
        fi
    else
        echo "Пожалуйста, введите допустимый номер порта (1-65535)."
    fi
done

# Показать существующие подсети
echo "Текущие конфигурации интерфейсов сети:"
ip a | grep inet
log "Просмотр текущих конфигураций интерфейсов сети."

# Запрашиваем подсеть с валидацией
while true; do
    read -p "Введите подсеть (например, 172.16.0.0/24): " subnet
    if is_valid_cidr "$subnet"; then
        log "Выбрана подсеть: $subnet"
        break
    else
        echo "Неверный формат подсети. Пожалуйста, введите корректную подсеть в формате X.X.X.X/YY."
    fi
done

# Запрашиваем список доступных IP с возможностью оставить пустым
read -p "Введите список доступных IP через пробел (оставьте пустым для 0.0.0.0/0): " -a allowed_ips

# Если список IP пустой, используем 0.0.0.0/0
if [[ "${#allowed_ips[@]}" -eq 0 ]]; then
    allowed_ips=("0.0.0.0/0")
    log "Список разрешенных IP пуст. Установлено значение по умолчанию: 0.0.0.0/0"
else
    log "Введенные разрешенные IP: ${allowed_ips[*]}"
fi

# Валидация каждого IP в allowed_ips
for ip in "${allowed_ips[@]}"; do
    if ! is_valid_cidr "$ip" && ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "Неверный IP-адрес или подсеть: $ip"
        log "Неверный IP-адрес или подсеть: $ip"
        exit 1
    fi
done

# Определяем интерфейс по умолчанию
DEFAULT_IF=$(ip route | awk '/default/ {print $5; exit}')

# Проверка существования интерфейса
if [[ -z "$DEFAULT_IF" ]]; then
    echo -e "\e[31mНе удалось определить интерфейс по умолчанию.\e[0m"
    log "Не удалось определить интерфейс по умолчанию."
    exit 1
fi

# Получаем IP-адрес интерфейса по умолчанию
DEFAULT_IP=$(ip addr show "$DEFAULT_IF" | grep 'inet ' | awk '{print $2}' | awk -F/ '{print $1}' | head -n 1)

if [[ -z "$DEFAULT_IP" ]]; then
    echo -e "\e[31mНе удалось определить IP-адрес интерфейса $DEFAULT_IF.\e[0m"
    log "Не удалось определить IP-адрес интерфейса $DEFAULT_IF."
    exit 1
fi

echo "Интерфейс по умолчанию: $DEFAULT_IF с IP: $DEFAULT_IP"
log "Интерфейс по умолчанию: $DEFAULT_IF с IP: $DEFAULT_IP"

# Создаём директорию для конфигурации, если её нет
CONFIG_DIR="${CONFIG_BASE_DIR}/${config_name}"
if [[ ! -d "$CONFIG_DIR" ]]; then
    mkdir -p "$CONFIG_DIR" || { echo "Ошибка создания директории ${CONFIG_DIR}"; log "Ошибка создания директории ${CONFIG_DIR}"; exit 1; }
    log "Создана директория конфигурации: $CONFIG_DIR"
fi

# Генерация ключей
log "Генерация ключей сервера для ${config_name}..."
echo "Генерация ключей сервера..."
if ! awg genkey | tee "${CONFIG_DIR}/privatekey" | awg pubkey | tee "${CONFIG_DIR}/publickey" > /dev/null; then
    echo "Ошибка генерации ключей."
    log "Ошибка генерации приватного или публичного ключа."
    exit 1
fi

if ! awg genpsk | tee "${CONFIG_DIR}/presharedkey" > /dev/null; then
    echo "Ошибка генерации presharedkey."
    log "Ошибка генерации presharedkey."
    exit 1
fi

# Устанавливаем безопасные разрешения на приватный ключ
chmod 600 "${CONFIG_DIR}/privatekey"
log "Установлены права доступа 600 на приватный ключ."

log "Ключи сервера для ${config_name} сгенерированы."
echo "Ключи сервера сгенерированы."

# Генерация параметров обфускации
log "Генерация параметров обфускации..."
Jc=$(shuf -i 1-128 -n 1)
Jmin=$(shuf -i 10-100 -n 1)
Jmax=$(shuf -i $((Jmin + 1))-1280 -n 1)

# Генерация параметров S и H
S1=$(shuf -i 0-128 -n 1)
S2=$(shuf -i 0-256 -n 1)
H1=$(shuf -i 0-1646644382 -n 1)
H2=$(shuf -i $((H1 + 1))-1646644382 -n 1)
H3=$(shuf -i $((H2 + 1))-1646644382 -n 1)
H4=$(shuf -i $((H3 + 1))-1646644382 -n 1)

log "Параметры обфускации: Jc=${Jc}, Jmin=${Jmin}, Jmax=${Jmax}, S1=${S1}, S2=${S2}, H1=${H1}, H2=${H2}, H3=${H3}, H4=${H4}"
echo "Параметры обфускации сгенерированы."

# Получаем внешний IP
echo "Получение внешнего IP сервера..."
if ! EXTERNAL_IP=$(curl -s http://checkip.amazonaws.com); then
    echo "Ошибка получения внешнего IP с помощью curl."
    log "Ошибка получения внешнего IP с помощью curl."
    exit 1
fi
log "Внешний IP сервера: ${EXTERNAL_IP}"
echo "Внешний IP сервера: ${EXTERNAL_IP}"

# Извлекаем WG_IP из подсети (например, из 172.17.33.1/24 извлекаем 172.17.33.1)
WG_IP=$(echo "$subnet" | awk -F/ '{print $1}')

# Проверка корректности WG_IP
if [[ -z "$WG_IP" ]]; then
    echo -e "\e[31mНе удалось извлечь IP-адрес из подсети $subnet.\e[0m"
    log "Не удалось извлечь IP-адрес из подсети $subnet."
    exit 1
fi

# Добавляем MASQUERADE правило для подсети WG
echo "Добавление iptables правила MASQUERADE для подсети $subnet..."
if iptables -t nat -A POSTROUTING -s "$subnet" -o "$DEFAULT_IF" -j MASQUERADE; then
    log "Добавлено iptables правило MASQUERADE для подсети $subnet."
    echo "Добавлено iptables правило MASQUERADE для подсети $subnet."
else
    echo -e "\e[31mОшибка добавления iptables правила MASQUERADE для подсети $subnet.\e[0m"
    log "Ошибка добавления iptables правила MASQUERADE для подсети $subnet."
    exit 1
fi

# Добавляем правило маршрутизации для WG_IP
echo "Добавление ip rule от $WG_IP в таблицу main..."
if ip rule add from "$WG_IP" table main; then
    log "Добавлено ip rule от $WG_IP в таблицу main."
    echo "Добавлено ip rule от $WG_IP в таблицу main."
else
    echo -e "\e[31mОшибка добавления ip rule от $WG_IP.\e[0m"
    log "Ошибка добавления ip rule от $WG_IP."
    exit 1
fi

# Создание конфигурационного файла
log "Создание конфигурационного файла для ${config_name}..."
echo "Создание конфигурационного файла..."
# Формируем список AllowedIPs как запятую-разделенный список
ALLOWED_IPS=$(IFS=, ; echo "${allowed_ips[*]}")

# Генерация правил iptables и сохранение их в переменные
iptables_rules_up=$(generate_iptables_rules "$config_name" "$WG_IP" "${allowed_ips[@]}")
iptables_rules_down=$(generate_iptables_rules "$config_name" "$WG_IP" "${allowed_ips[@]}")

# Запись конфигурации в файл с использованием переменных
cat > "${CONFIG_DIR}/${config_name}.conf" << EOF
[Interface]
PrivateKey = $(cat "${CONFIG_DIR}/privatekey")
Address = ${subnet}
ListenPort = ${port}
PostUp = iptables -t nat -A POSTROUTING -s ${subnet} -o ${DEFAULT_IF} -j MASQUERADE; ip rule add from ${WG_IP} table main; $iptables_rules_up
PostDown = iptables -t nat -D POSTROUTING -s ${subnet} -o ${DEFAULT_IF} -j MASQUERADE; ip rule del from ${WG_IP} table main; $iptables_rules_down
$iptables_rules_down
##
Jc = ${Jc}
Jmin = ${Jmin}
Jmax = ${Jmax}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}

[Peer]
PublicKey = $(cat "${CONFIG_DIR}/publickey")
PresharedKey = $(cat "${CONFIG_DIR}/presharedkey")
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepAlive = 25
EOF

log "Конфигурационный файл создан: ${CONFIG_DIR}/${config_name}.conf"
echo "Конфигурационный файл создан: ${CONFIG_DIR}/${config_name}.conf"

# Создание systemd юнита для awg-quick
log "Создание systemd юнита для awg-quick@${config_name}.service..."
echo "Создание systemd юнита для awg-quick@${config_name}.service..."
systemd_unit_path="/etc/systemd/system/awg-quick@${config_name}.service"

sudo tee "$systemd_unit_path" > /dev/null << EOM
[Unit]
Description=Amnezia WireGuard Interface ${config_name}
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/awg-quick up ${CONFIG_DIR}/${config_name}.conf
ExecStop=/usr/bin/awg-quick down ${CONFIG_DIR}/${config_name}.conf

[Install]
WantedBy=multi-user.target
EOM

log "Systemd юнит awg-quick@${config_name}.service создан."
echo "Systemd юнит awg-quick@${config_name}.service создан."

# Перезагрузка systemd для применения новых юнитов
log "Перезагрузка systemd..."
echo "Перезагрузка systemd..."
systemctl daemon-reload
log "systemd перезагружен."

# Включение systemd юнита для автозапуска
log "Включение systemd юнита awg-quick@${config_name}.service для автозапуска..."
echo "Включение systemd юнита awg-quick@${config_name}.service для автозапуска..."
systemctl enable "awg-quick@${config_name}.service" >/dev/null
log "Systemd юнит awg-quick@${config_name}.service включен для автозапуска."

# Запуск systemd юнита
log "Запуск systemd юнита awg-quick@${config_name}.service..."
echo "Запуск systemd юнита awg-quick@${config_name}.service..."
systemctl start "awg-quick@${config_name}.service"

# Проверка статуса сервиса и вывод результата
if systemctl is-active --quiet "awg-quick@${config_name}.service"; then
    log "Сервис awg-quick@${config_name}.service успешно запущен."
    echo -e "\e[32mКонфигурация для ${config_name} успешно создана и сервис запущен.\e[0m"
    echo "Конфигурация сохранена в ${CONFIG_DIR}/${config_name}.conf"
    echo "Статус сервиса:"
    systemctl status "awg-quick@${config_name}.service" --no-pager
else
    log "Сервис awg-quick@${config_name}.service не запустился."
    echo -e "\e[31mНе удалось запустить сервис awg-quick@${config_name}.service.\e[0m"
    echo "Проверьте логи для подробной информации."
    exit 1
fi

# Удаляем ловушку, если все прошло успешно
trap - EXIT