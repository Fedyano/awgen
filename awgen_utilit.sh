#!/bin/bash

# Включение строгого режима
set -euo pipefail
IFS=$'\n\t'

# Лог-файл развертывания
DEPLOY_LOG="/var/log/awgen_deploy.log"

# Функция для логирования в консоль и файл
log_deploy() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$DEPLOY_LOG"
}

# Функция для отката изменений
rollback() {
    log_deploy "Ошибка во время развертывания. Выполняется откат..."
    # Команды для отката изменений
    sudo rm -f /usr/local/bin/awgen
    sudo rm -f /etc/profile.d/awgen.sh
    sudo rm -f /usr/local/bin/awgdecoder.jar
    # Не удаляем /etc/amnezia/amneziawg, чтобы сохранить конфигурационные файлы
    log_deploy "Откат завершён."
    exit 1
}

# Установка ловушки на ошибку
trap rollback ERR

log_deploy "Начало развертывания утилиты awgen..."

# Функция для удаления существующей утилиты awgen
remove_existing_awgen() {
    if command -v awgen &> /dev/null; then
        log_deploy "Найдена существующая утилита awgen. Удаление..."
        sudo rm -f /usr/local/bin/awgen
        sudo rm -f /etc/profile.d/awgen.sh
        sudo rm -f /usr/local/bin/awgdecoder.jar
        log_deploy "Существующая утилита awgen удалена."
    else
        log_deploy "Утилита awgen не установлена. Продолжаем установку."
    fi
}

# Вызов функции удаления существующей утилиты
remove_existing_awgen

# Создание директории для конфигураций, если не существует
if [[ ! -d /etc/amnezia/amneziawg ]]; then
    sudo mkdir -p /etc/amnezia/amneziawg
    log_deploy "Создана директория /etc/amnezia/amneziawg."
else
    log_deploy "Директория /etc/amnezia/amneziawg уже существует."
fi

# Создание утилиты awgen
log_deploy "Создание утилиты awgen..."
sudo tee /usr/local/bin/awgen > /dev/null << 'EOM'
#!/bin/bash

# Функция для логирования
log() {
    local config=$1
    shift
    mkdir -p /etc/amnezia/amneziawg/"$config"/logs
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >> /etc/amnezia/amneziawg/"$config"/logs/$(date +'%d.%m.%Y').log
}

# Функция для форматирования байтов
format_bytes() {
    local bytes=$1
    local unit="bytes"
    if [[ $bytes -ge 1073741824 ]]; then
        bytes=$(echo "scale=2; $bytes / 1073741824" | bc)
        unit="GB"
    elif [[ $bytes -ge 1048576 ]]; then
        bytes=$(echo "scale=2; $bytes / 1048576" | bc)
        unit="MB"
    elif [[ $bytes -ge 1024 ]]; then
        bytes=$(echo "scale=2; $bytes / 1024" | bc)
        unit="KB"
    fi
    echo "$bytes $unit"
}

# Функция для чтения параметров обфускации из серверной конфигурации
read_obfuscation_params() {
    local config=$1
    local config_file="/etc/amnezia/amneziawg/$config/$config.conf"

    if [[ ! -f "$config_file" ]]; then
        echo "Серверная конфигурация $config не найдена."
        exit 1
    fi

    # Используем grep для поиска параметров в любом месте файла
    Jc=$(grep -E '^\s*Jc\s*=' "$config_file" | awk -F'=' '{print $2}' | tr -d ' ')
    Jmin=$(grep -E '^\s*Jmin\s*=' "$config_file" | awk -F'=' '{print $2}' | tr -d ' ')
    Jmax=$(grep -E '^\s*Jmax\s*=' "$config_file" | awk -F'=' '{print $2}' | tr -d ' ')
    S1=$(grep -E '^\s*S1\s*=' "$config_file" | awk -F'=' '{print $2}' | tr -d ' ')
    S2=$(grep -E '^\s*S2\s*=' "$config_file" | awk -F'=' '{print $2}' | tr -d ' ')
    H1=$(grep -E '^\s*H1\s*=' "$config_file" | awk -F'=' '{print $2}' | tr -d ' ')
    H2=$(grep -E '^\s*H2\s*=' "$config_file" | awk -F'=' '{print $2}' | tr -d ' ')
    H3=$(grep -E '^\s*H3\s*=' "$config_file" | awk -F'=' '{print $2}' | tr -d ' ')
    H4=$(grep -E '^\s*H4\s*=' "$config_file" | awk -F'=' '{print $2}' | tr -d ' ')

    # Проверка, что все параметры найдены
    if [[ -z "$Jc" || -z "$Jmin" || -z "$Jmax" || -z "$S1" || -z "$S2" || -z "$H1" || -z "$H2" || -z "$H3" || -z "$H4" ]]; then
        echo "Не все параметры обфускации найдены в конфигурации $config."
        exit 1
    fi
}

# Функция добавления клиента
add_client() {
    local config=$1
    local CLIENT_NAME=$2
    local ALLOWED_IPS=$3
    local EXTERNAL_HOST=$4
    local CLIENT_DIR="/etc/amnezia/amneziawg/$config/clients/${CLIENT_NAME}"
    local CLIENT_PRIVATEKEY="${CLIENT_DIR}/${CLIENT_NAME}.private.key"
    local CLIENT_PUBLICKEY="${CLIENT_DIR}/${CLIENT_NAME}.public.key"
    local CLIENT_CONF="${CLIENT_DIR}/${CLIENT_NAME}.conf"

    # Проверка существования директории клиента
    if [[ -d "$CLIENT_DIR" ]]; then
        echo "Клиент $CLIENT_NAME уже существует в конфигурации $config."
        return 1
    fi

    mkdir -p "${CLIENT_DIR}"
    awg genkey | tee "${CLIENT_PRIVATEKEY}" | awg pubkey | tee "${CLIENT_PUBLICKEY}"
    if [[ $? -ne 0 ]]; then
        echo "Ошибка при генерации ключей для клиента $CLIENT_NAME."
        return 1
    fi

    local SERVER_PUBLICKEY
    local PRESHARED_KEY
    SERVER_PUBLICKEY=$(cat /etc/amnezia/amneziawg/"$config"/public.key)
    PRESHARED_KEY=$(cat /etc/amnezia/amneziawg/"$config"/preshared.key)

    # Чтение параметров обфускации
    read_obfuscation_params "$config"

    # Определение BASE_SUBNET
    BASE_SUBNET=$(grep -m1 '^Address' /etc/amnezia/amneziawg/"$config"/"$config".conf | awk '{print $3}' | cut -d'/' -f1 | cut -d'.' -f1-3)

    # Поиск свободного IP-адреса
    USED_IPS=$(grep -Eo "${BASE_SUBNET}\.[0-9]+" /etc/amnezia/amneziawg/"$config"/"$config".conf | awk -F. '{print $4}')
    for i in {2..254}; do
        if ! echo "$USED_IPS" | grep -qw "$i"; then
            CLIENT_IP="${BASE_SUBNET}.$i"
            break
        fi
    done

    if [[ -z "$CLIENT_IP" ]]; then
        echo "Не удалось найти свободный IP-адрес."
        return 1
    fi

    # Добавление клиента в серверную конфигурацию
    tee -a /etc/amnezia/amneziawg/"$config"/"$config".conf > /dev/null << EOC
#${CLIENT_NAME}
[Peer]
PublicKey = $(cat "${CLIENT_PUBLICKEY}")
PresharedKey = ${PRESHARED_KEY}
AllowedIPs = ${CLIENT_IP}/32
EOC

    # Определение порта прослушивания
    LISTEN_PORT=$(grep "ListenPort" /etc/amnezia/amneziawg/"$config"/"$config".conf | awk '{print $3}')
    if [[ -z "$LISTEN_PORT" ]]; then
        echo "Не удалось определить ListenPort из конфигурации."
        return 1
    fi

    # Генерация клиентской конфигурации
    tee "${CLIENT_CONF}" > /dev/null << EOC
[Interface]
PrivateKey = $(cat "${CLIENT_PRIVATEKEY}")
Address = ${CLIENT_IP}/24
DNS = 1.1.1.1, 1.0.0.1
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
PublicKey = ${SERVER_PUBLICKEY}
PresharedKey = ${PRESHARED_KEY}
Endpoint = ${EXTERNAL_HOST}:${LISTEN_PORT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepAlive = 25
EOC

    # Перезапуск сервиса
    if systemctl restart awg-quick@"$config"; then
        qrencode -t ansiutf8 < "${CLIENT_CONF}" > "${CLIENT_DIR}/qrcode.txt"
    else
        echo "Не удалось перезапустить сервис awg-quick@$config."
        systemctl status awg-quick@"$config"
        return 1
    fi

    echo -e "\e[32mClient configuration ${CLIENT_NAME}:\e[0m"
    cat "${CLIENT_CONF}"
    echo -e "\e[32mQR code for client ${CLIENT_NAME}:\e[0m"
    cat "${CLIENT_DIR}/qrcode.txt"

    log "$config" "Client ${CLIENT_NAME} added."
    return 0
}

# Функция остановки клиента
stop_client() {
    local config=$1
    local CLIENT_NAME=$2
    local CLIENT_PUBLICKEY
    CLIENT_PUBLICKEY=$(cat /etc/amnezia/amneziawg/"$config"/clients/"$CLIENT_NAME"/"${CLIENT_NAME}".public.key)

    if grep -q "${CLIENT_PUBLICKEY}" /etc/amnezia/amneziawg/"$config"/"$config".conf; then
        sed -i "/#${CLIENT_NAME}/,+4d" /etc/amnezia/amneziawg/"$config"/"$config".conf
        echo "Client ${CLIENT_NAME} stopped."
        if systemctl restart awg-quick@"$config"; then
            log "$config" "Client ${CLIENT_NAME} stopped."
            return 0
        else
            echo "Не удалось перезапустить сервис awg-quick@$config."
            return 1
        fi
    else
        echo "Client ${CLIENT_NAME} is not active."
        return 1
    fi
}

# Функция запуска клиента
start_client() {
    local config=$1
    local CLIENT_NAME=$2
    local CLIENT_PUBLICKEY
    CLIENT_PUBLICKEY=$(cat /etc/amnezia/amneziawg/"$config"/clients/"$CLIENT_NAME"/"${CLIENT_NAME}".public.key)
    local CLIENT_CONF="/etc/amnezia/amneziawg/$config/clients/${CLIENT_NAME}/${CLIENT_NAME}.conf"
    local CLIENT_IP
    CLIENT_IP=$(grep "Address" "${CLIENT_CONF}" | awk '{print $3}' | cut -d/ -f1)
    local PRESHARED_KEY
    PRESHARED_KEY=$(cat /etc/amnezia/amneziawg/"$config"/preshared.key)

    if ! grep -q "${CLIENT_PUBLICKEY}" /etc/amnezia/amneziawg/"$config"/"$config".conf; then
        tee -a /etc/amnezia/amneziawg/"$config"/"$config".conf > /dev/null << EOC
#${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUBLICKEY}
PresharedKey = ${PRESHARED_KEY}
AllowedIPs = ${CLIENT_IP}/32
EOC
        echo "Client ${CLIENT_NAME} started."
        if systemctl restart awg-quick@"$config"; then
            log "$config" "Client ${CLIENT_NAME} started."
            return 0
        else
            echo "Не удалось перезапустить сервис awg-quick@$config."
            return 1
        fi
    else
        echo "Client ${CLIENT_NAME} is already active."
        return 1
    fi
}

# Функция удаления клиента
delete_client() {
    local config=$1
    local CLIENT_NAME=$2
    local CLIENT_PUBLICKEY
    CLIENT_PUBLICKEY=$(cat /etc/amnezia/amneziawg/"$config"/clients/"$CLIENT_NAME"/"${CLIENT_NAME}".public.key)
    sed -i "/#${CLIENT_NAME}/,+4d" /etc/amnezia/amneziawg/"$config"/"$config".conf
    rm -rf /etc/amnezia/amneziawg/"$config"/clients/"$CLIENT_NAME"
    echo "Client ${CLIENT_NAME} deleted."
    if systemctl restart awg-quick@"$config" || true; then
        log "$config" "Client ${CLIENT_NAME} deleted."
        return 0
    else
        echo "Не удалось перезапустить сервис awg-quick@$config."
        return 1
    fi
}

# Функция отображения информации о клиенте
show_client() {
    local config=$1
    local CLIENT_NAME=$2
    local CLIENT_CONF="/etc/amnezia/amneziawg/$config/clients/${CLIENT_NAME}/${CLIENT_NAME}.conf"
    if [[ -f "${CLIENT_CONF}" ]]; then
        echo -e "\e[32mClient configuration ${CLIENT_NAME}:\e[0m"
        cat "${CLIENT_CONF}"
        echo -e "\e[32mQR code for client ${CLIENT_NAME}:\e[0m"
        qrencode -t ansiutf8 < "${CLIENT_CONF}"
    else
        echo "Configuration for client ${CLIENT_NAME} not found."
        return 1
    fi
}

# Функция отображения всех клиентов
show_clients() {
    local config=$1
    local client_count=1
    for client_dir in /etc/amnezia/amneziawg/"$config"/clients/*; do
        if [[ -d "$client_dir" ]]; then
            local client_name
            client_name=$(basename "$client_dir")
            local endpoint
            endpoint=$(awg show "$config" endpoints | grep "$(cat "$client_dir/$client_name/$client_name.public.key")" | awk '{print $2}')
            local allowed_ips
            allowed_ips=$(awg show "$config" allowed-ips | grep "$(cat "$client_dir/$client_name/$client_name.public.key")" | awk '{print $2}')
            local last_handshake
            last_handshake=$(awg show "$config" latest-handshakes | grep "$(cat "$client_dir/$client_name/$client_name.public.key")" | awk '{print $2}')
            local transfer_rx
            transfer_rx=$(awg show "$config" transfer | grep "$(cat "$client_dir/$client_name/$client_name.public.key")" | awk '{print $2}')
            local transfer_tx
            transfer_tx=$(awg show "$config" transfer | grep "$(cat "$client_dir/$client_name/$client_name.public.key")" | awk '{print $3}')
            local formatted_rx
            formatted_rx=$(format_bytes "${transfer_rx}")
            local formatted_tx
            formatted_tx=$(format_bytes "${transfer_tx}")
            echo -e "\e[32mClient ${client_count}: ${client_name}\e[0m"
            echo "External IP: ${endpoint:-none}"
            echo "Internal IP: ${allowed_ips:-none}"
            if [[ -n "$last_handshake" && "$last_handshake" != "0" ]]; then
                echo "Last handshake: $(date -d @"$last_handshake" +'%d-%m-%Y %H:%M:%S')"
            else
                echo "Last handshake: not yet"
            fi
            echo "Traffic RX: ${formatted_rx}"
            echo "Traffic TX: ${formatted_tx}"
            echo ""
            client_count=$((client_count + 1))
        fi
    done
}

# Функция генерации VPN URL
generate_vpn_url() {
    local config=$1
    local CLIENT_NAME=$2
    local CLIENT_CONF="/etc/amnezia/amneziawg/$config/clients/${CLIENT_NAME}/${CLIENT_NAME}.conf"
    local CLIENT_VPN="/etc/amnezia/amneziawg/$config/clients/${CLIENT_NAME}/${CLIENT_NAME}.vpn"

    if [[ ! -f "$CLIENT_CONF" ]]; then
        echo "Configuration file for client ${CLIENT_NAME} not found."
        return 1
    fi

    if [[ ! -f "/usr/local/bin/awgdecoder.jar" ]]; then
        echo "awgdecoder.jar not found. Please install it in /usr/local/bin."
        return 1
    fi

    java -jar /usr/local/bin/awgdecoder.jar encode -i "$CLIENT_CONF" -d 1.1.1.1:1.0.0.1 -of conf > "$CLIENT_VPN"
    if [[ $? -ne 0 ]]; then
        echo "Error creating .vpn file for client ${CLIENT_NAME}."
        return 1
    fi

    if [[ ! -f "$CLIENT_VPN" ]]; then
        echo "Error creating .vpn file for client ${CLIENT_NAME}."
        return 1
    fi

    local VPN_URL
    VPN_URL=$(cat "$CLIENT_VPN")

    echo -e "\e[32mVPN URL for client ${CLIENT_NAME}:\e[0m"
    echo "$VPN_URL"
    log "$config" "VPN URL generated for client ${CLIENT_NAME}."
    return 0
}

# Функция создания бэкапов конфигураций
backup_configurations() {
    local config=$1
    local backup_dir="/etc/amnezia/amneziawg/$config/backups"
    local backup_file="$backup_dir/$(date +'%d.%m.%Y')-backup.tar"
    mkdir -p "$backup_dir"
    tar --exclude="$backup_file" -cvf "$backup_file" -C /etc/amnezia/amneziawg/"$config" .
    if [[ $? -ne 0 ]]; then
        echo "Ошибка при создании бэкапа конфигурации $config."
        return 1
    fi
    log "$config" "Configurations backed up to ${backup_file}."

    # Хранить только последние 4 бэкапа
    local backup_count
    backup_count=$(ls -1 "$backup_dir"/*.tar 2>/dev/null | wc -l)
    if [[ "$backup_count" -gt 4 ]]; then
        local oldest_backup
        oldest_backup=$(ls -t "$backup_dir"/*.tar | tail -1)
        rm "$oldest_backup"
        log "$config" "Deleted oldest backup: $oldest_backup"
    fi
    return 0
}

# Функция восстановления из бэкапа
restore_from_backup() {
    local config=$1
    local backup_file
    backup_file=$(ls /root/*.tar 2>/dev/null | grep -E "backup.*\.tar$" | head -n 1)

    if [[ -f "$backup_file" ]]; then
        log "$config" "Restoring from backup: $backup_file"

        # Удалить текущую конфигурацию, но оставить /etc/amnezia/amneziawg/"$config"/clients
        sudo rm -rf /etc/amnezia/amneziawg/"$config"/*
        # Воссоздать необходимые директории
        mkdir -p /etc/amnezia/amneziawg/"$config"/clients
        mkdir -p /etc/amnezia/amneziawg/"$config"/logs
        mkdir -p /etc/amnezia/amneziawg/"$config"/backups

        # Извлечь бэкап
        tar -xvf "$backup_file" -C /etc/amnezia/amneziawg/"$config" --strip-components=1 > /dev/null 2>&1
        wait

        if [[ $? -ne 0 ]]; then
            echo "Ошибка при извлечении бэкапа."
            return 1
        fi

        log "$config" "Backup restored from $backup_file"

        # Перезапустить туннель
        log "$config" "Restarting $config interface..."
        if awg-quick down "$config" && awg-quick up "$config"; then
            wait
            log "$config" "Interface $config restarted"
            echo -e "\e[32mRestoration complete. Amnezia-WG $config has been restored from backup.\e[0m"
            return 0
        else
            echo "Не удалось перезапустить интерфейс $config."
            return 1
        fi
    else
        echo -e "\e[31mNo valid backup file found in /root directory.\e[0m"
        log "$config" "No valid backup file found in /root directory."
        return 1
    fi
}

# Функция деинсталляции сервера
uninstall_server() {
    local config=$1
    log "$config" "Stopping and removing the $config interface..."

    if awg-quick down "$config"; then
        log "$config" "Interface $config stopped."
    else
        log "$config" "Interface $config could not be stopped or was already stopped."
    fi
    if ip link delete "$config" 2>/dev/null; then
        log "$config" "Interface $config deleted."
    else
        log "$config" "Interface $config could not be deleted or does not exist."
    fi
    wait

    log "$config" "Removing Amnezia-WG package..."

    sudo apt-get remove --purge -y amneziawg > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        log "$config" "Amnezia-WG package removed."
    else
        log "$config" "Failed to remove Amnezia-WG package."
    fi
    wait

    log "$config" "Removing additional packages..."

    sudo apt-get remove --purge -y software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r) qrencode bc openjdk-17-jre-headless > /dev/null 2>&1
    sudo apt-get autoremove -y > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        log "$config" "Additional packages removed."
    else
        log "$config" "Failed to remove some additional packages."
    fi
    wait

    log "$config" "Removing configuration and log files..."

    sudo rm -rf /etc/amnezia/amneziawg/"$config"
    if [[ $? -eq 0 ]]; then
        log "$config" "Configuration and log files removed."
    else
        log "$config" "Failed to remove some configuration or log files."
    fi
    wait

    log "$config" "Removing awgen and awgdecoder.jar utilities..."

    sudo rm -f /usr/local/bin/awgen /usr/local/bin/awgdecoder.jar
    if [[ $? -eq 0 ]]; then
        log "$config" "awgen and awgdecoder.jar utilities removed."
    else
        log "$config" "Failed to remove some utilities."
    fi
    wait

    log "$config" "Removing systemd service..."

    sudo systemctl disable awg-quick@"$config" > /dev/null 2>&1 || true
    sudo rm -f /etc/systemd/system/awg-quick@"$config".service
    sudo systemctl daemon-reload
    if [[ $? -eq 0 ]]; then
        log "$config" "Systemd service removed."
    else
        log "$config" "Failed to remove systemd service."
    fi
    wait

    log "$config" "Removing cron jobs..."

    (crontab -l 2>/dev/null | grep -v "find /etc/amnezia/amneziawg/$config/logs/") | crontab -
    (crontab -l 2>/dev/null | grep -v "ls -t /etc/amnezia/amneziawg/$config/backups/") | crontab -
    if [[ $? -eq 0 ]]; then
        log "$config" "Cron jobs removed."
    else
        log "$config" "Failed to remove some cron jobs."
    fi
    wait

    echo -e "\e[32mUninstallation complete for configuration $config. Amnezia-WG and related components have been removed.\e[0m"
    log "$config" "Uninstallation complete."
    return 0
}

# Функция вывода информации о всех конфигурациях
confs_info() {
    local config_dir="/etc/amnezia/amneziawg"
    if [[ ! -d "$config_dir" ]]; then
        echo -e "\e[31mNo configurations found in $config_dir.\e[0m"
        return 1
    fi

    echo -e "\e[32mAvailable Configurations:\e[0m"

    for config_path in "$config_dir"/*/; do
        # Проверка, что это директория
        if [[ -d "$config_path" ]]; then
            local config=$(basename "$config_path")
            local config_file="$config_path/$config.conf"

            # Проверка наличия конфигурационного файла
            if [[ ! -f "$config_file" ]]; then
                echo -e "\e[33m- $config: Configuration file not found.\e[0m"
                continue
            fi

            # Извлечение ListenPort
            local listen_port
            listen_port=$(grep "ListenPort" "$config_file" | awk '{print $3}')
            listen_port=${listen_port:-"Not set"}

            # Получение внешнего IP-адреса сервера
            local external_ip
            external_ip=$(awk '/Endpoint/ {print $3}' "$config_file" | cut -d':' -f1)
            external_ip=${external_ip:-"Not detected"}

            # Подсчет общего количества клиентов
            local total_clients
            total_clients=$(find "$config_path/clients/" -mindepth 1 -maxdepth 1 -type d | wc -l)

            # Подсчет количества активных клиентов
            local active_clients
            active_clients=$(awg show "$config" allowed-ips | grep -c "0.0.0.0/0")

            # Вывод информации о конфигурации
            echo -e "\e[34m- Configuration: $config\e[0m"
            echo "  External IP: $external_ip"
            echo "  Listen Port: $listen_port"
            echo "  Total Clients: $total_clients"
            echo "  Active Clients: $active_clients"
            echo ""
        fi
    done
    return 0
}

# Функция вывода полной информации об указанной конфигурации
conf_info() {
    local config=$1
    local config_path="/etc/amnezia/amneziawg/$config"

    if [[ ! -d "$config_path" ]]; then
        echo -e "\e[31mConfiguration '$config' does not exist.\e[0m"
        return 1
    fi

    local config_file="$config_path/$config.conf"

    if [[ ! -f "$config_file" ]]; then
        echo -e "\e[31mConfiguration file '$config.conf' not found for '$config'.\e[0m"
        return 1
    fi

    echo -e "\e[32mConfiguration Information for '$config':\e[0m"
    echo "----------------------------------------"

    # Чтение и вывод основных параметров конфигурационного файла
    grep -E '^\s*(ListenPort|PresharedKey|PublicKey|AllowedIPs)' "$config_file" | while read -r line; do
        echo "$line"
    done
    echo ""

    # Получение общего количества клиентов
    local total_clients
    total_clients=$(find "$config_path/clients/" -mindepth 1 -maxdepth 1 -type d | wc -l)
    echo "Total Clients: $total_clients"

    # Получение количества активных клиентов
    local active_clients
    active_clients=$(awg show "$config" allowed-ips | grep -c "0.0.0.0/0")
    echo "Active Clients: $active_clients"
    echo ""

    echo -e "\e[34mClients Details:\e[0m"

    for client_dir in "$config_path"/clients/*; do
        if [[ -d "$client_dir" ]]; then
            local client_name
            client_name=$(basename "$client_dir")
            local client_conf="$client_dir/$client_name.conf"

            if [[ ! -f "$client_conf" ]]; then
                echo -e "\e[33m- $client_name: Configuration file not found.\e[0m"
                continue
            fi

            # Извлечение PublicKey клиента
            local client_publickey
            client_publickey=$(grep "PublicKey" "$client_conf" | awk '{print $3}')

            # Проверка активности клиента
            if grep -q "$client_publickey" "$config_file"; then
                local status="Active"
                # Извлечение дополнительной информации о клиенте
                local endpoint
                endpoint=$(awk -v pk="$client_publickey" '/Endpoint/ && $0 ~ pk {print $3}' "$config_file")
                endpoint=${endpoint:-"Not set"}

                local allowed_ips
                allowed_ips=$(awk -v pk="$client_publickey" '/AllowedIPs/ && $0 ~ pk {print $3}' "$config_file")

                local last_handshake
                last_handshake=$(awg show "$config" latest-handshakes | grep "$client_publickey" | awk '{print $2}')
                last_handshake=${last_handshake:-"Never"}

                local transfer_rx
                transfer_rx=$(awg show "$config" transfer | grep "$client_publickey" | awk '{print $2}')
                transfer_rx=$(format_bytes "$transfer_rx")

                local transfer_tx
                transfer_tx=$(awg show "$config" transfer | grep "$client_publickey" | awk '{print $3}')
                transfer_tx=$(format_bytes "$transfer_tx")

                echo -e "\e[32m- $client_name:\e[0m"
                echo "  Status: $status"
                echo "  Endpoint: ${endpoint:-none}"
                echo "  Allowed IPs: ${allowed_ips:-none}"
                echo "  Last Handshake: ${last_handshake}"
                echo "  Traffic RX: ${transfer_rx}"
                echo "  Traffic TX: ${transfer_tx}"
                echo ""
            else
                local status="Inactive"
                echo -e "\e[31m- $client_name:\e[0m"
                echo "  Status: $status"
                echo ""
            fi
        fi
    done

    return 0
}


# Обновление cron задач для очистки логов и управления бэкапами
update_cron_jobs() {
    local config=$1
    (crontab -l 2>/dev/null | grep -v "find /etc/amnezia/amneziawg/$config/logs/") | crontab -
    (crontab -l 2>/dev/null | grep -v "ls -t /etc/amnezia/amneziawg/$config/backups/") | crontab -
    (crontab -l 2>/dev/null; echo "0 0 * * 0 find /etc/amnezia/amneziawg/$config/logs/ -type f -mtime +14 -exec rm {} \;") | crontab -
    (crontab -l 2>/dev/null; echo "0 0 * * 1 ls -t /etc/amnezia/amneziawg/$config/backups/*.tar | tail -n +5 | xargs rm --") | crontab -
}

# Обработка аргументов командной строки
if [[ "$1" == "add" ]]; then
    if [[ -z "$2" || -z "$3" || -z "$4" || -z "$5" ]]; then
        echo "Usage: $0 add <config_name> <client_name> <allowed_ips> <external_host>"
        exit 1
    fi
    add_client "$2" "$3" "$4" "$5"
    exit $?
fi

if [[ "$1" == "stop" ]]; then
    if [[ -z "$2" || -z "$3" ]]; then
        echo "Usage: $0 stop <config_name> <client_name>"
        exit 1
    fi
    stop_client "$2" "$3"
    exit $?
fi

if [[ "$1" == "start" ]]; then
    if [[ -z "$2" || -z "$3" ]]; then
        echo "Usage: $0 start <config_name> <client_name>"
        exit 1
    fi
    start_client "$2" "$3"
    exit $?
fi

if [[ "$1" == "delete" ]]; then
    if [[ -z "$2" || -z "$3" ]]; then
        echo "Usage: $0 delete <config_name> <client_name>"
        exit 1
    fi
    delete_client "$2" "$3"
    exit $?
fi

if [[ "$1" == "show" ]]; then
    if [[ -z "$2" || -z "$3" ]]; then
        echo "Usage: $0 show <config_name> <client_name>"
        exit 1
    fi
    show_client "$2" "$3"
    exit $?
fi

if [[ "$1" == "clients" ]]; then
    if [[ -z "$2" ]]; then
        echo "Usage: $0 clients <config_name>"
        exit 1
    fi
    show_clients "$2"
    exit $?
fi

if [[ "$1" == "awdecode" ]]; then
    if [[ -z "$2" || -z "$3" ]]; then
        echo "Usage: $0 awdecode <config_name> <client_name>"
        exit 1
    fi
    generate_vpn_url "$2" "$3"
    exit $?
fi

if [[ "$1" == "backup" ]]; then
    if [[ -z "$2" ]]; then
        echo "Usage: $0 backup <config_name>"
        exit 1
    fi
    backup_configurations "$2"
    exit $?
fi

if [[ "$1" == "restore" ]]; then
    if [[ -z "$2" ]]; then
        echo "Usage: $0 restore <config_name>"
        exit 1
    fi
    restore_from_backup "$2"
    exit $?
fi

if [[ "$1" == "uninstall" ]]; then
    if [[ -z "$2" ]]; then
        echo "Usage: $0 uninstall <config_name>"
        exit 1
    fi
    uninstall_server "$2"
    exit $?
fi

if [[ "$1" == "confs_info" ]]; then
    confs_info
    exit $?
fi

if [[ "$1" == "conf_info" ]]; then
    if [[ -z "$2" ]]; then
        echo "Usage: $0 conf_info <config_name>"
        exit 1
    fi
    conf_info "$2"
    exit $?
fi

# Интерфейс меню
echo -e "\e[32mAmnezia-WG Management Utility\e[0m"
echo "1. Add client(s)"
echo "2. Stop client(s)"
echo "3. Start client(s)"
echo "4. Delete client(s)"
echo "5. Show client(s)"
echo "6. Show statistics"
echo "7. Generate VPN URL"
echo "8. Backup"
echo "9. Restore from backup"
echo "10. Server uninstall"
echo "11. List all configurations"
echo "12. Show configuration info"
echo "13. Exit"
echo -n "Enter your choice (1-13): "
read -r option

case $option in
   1)
    echo -n "Enter configuration name: "
    read -r config
    if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
        echo "Configuration $config does not exist."
        exit 1
    fi

    echo -n "Enter client names separated by space: "
    read -r -a clients_array

    echo -n "Enter Allowed IPs for clients (e.g., '0.0.0.0/0' or '192.168.1.0/24,10.0.0.0/8'): "
    read -r allowed_ips
    if [[ -z "$allowed_ips" ]]; then
        echo "Allowed IPs cannot be empty."
        exit 1
    fi

    echo -n "Enter External Host (e.g., 'myserver.example.com'): "
    read -r external_host
    if [[ -z "$external_host" ]]; then
        echo "External Host cannot be empty."
        exit 1
    fi

    for client in "${clients_array[@]}"; do
        add_client "$config" "$client" "$allowed_ips" "$external_host"
        if [[ $? -ne 0 ]]; then
            echo "Failed to add client $client."
        else
            echo "Client $client added successfully."
        fi
    done
    ;;
    2)
        echo -n "Enter configuration name: "
        read -r config
        if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
            echo "Configuration $config does not exist."
            exit 1
        fi
        echo "Available clients in $config:"
        client_count=1
        for client_dir in /etc/amnezia/amneziawg/"$config"/clients/*; do
            if [[ -d "$client_dir" ]]; then
                client_name=$(basename "$client_dir")
                echo "${client_count}. ${client_name}"
                client_count=$((client_count + 1))
            fi
        done
        echo -n "Enter client names separated by space: "
        read -r clients
        for client in $clients; do
            stop_client "$config" "$client"
            if [[ $? -ne 0 ]]; then
                echo "Failed to stop client $client."
            fi
        done
        ;;
    3)
        echo -n "Enter configuration name: "
        read -r config
        if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
            echo "Configuration $config does not exist."
            exit 1
        fi
        echo "Available clients in $config:"
        client_count=1
        for client_dir in /etc/amnezia/amneziawg/"$config"/clients/*; do
            if [[ -d "$client_dir" ]]; then
                client_name=$(basename "$client_dir")
                echo "${client_count}. ${client_name}"
                client_count=$((client_count + 1))
            fi
        done
        echo -n "Enter client names separated by space: "
        read -r clients
        for client in $clients; do
            start_client "$config" "$client"
            if [[ $? -ne 0 ]]; then
                echo "Failed to start client $client."
            fi
        done
        ;;
    4)
        echo -n "Enter configuration name: "
        read -r config
        if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
            echo "Configuration $config does not exist."
            exit 1
        fi
        echo "Available clients in $config:"
        client_count=1
        for client_dir in /etc/amnezia/amneziawg/"$config"/clients/*; do
            if [[ -d "$client_dir" ]]; then
                client_name=$(basename "$client_dir")
                echo "${client_count}. ${client_name}"
                client_count=$((client_count + 1))
            fi
        done
        echo -n "Enter client names separated by space: "
        read -r clients
        for client in $clients; do
            delete_client "$config" "$client"
            if [[ $? -ne 0 ]]; then
                echo "Failed to delete client $client."
            fi
        done
        ;;
    5)
        echo -n "Enter configuration name: "
        read -r config
        if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
            echo "Configuration $config does not exist."
            exit 1
        fi
        echo "Available clients in $config:"
        client_count=1
        for client_dir in /etc/amnezia/amneziawg/"$config"/clients/*; do
            if [[ -d "$client_dir" ]]; then
                client_name=$(basename "$client_dir")
                echo "${client_count}. ${client_name}"
                client_count=$((client_count + 1))
            fi
        done
        echo -n "Enter client names separated by space: "
        read -r clients
        for client in $clients; do
            show_client "$config" "$client"
            if [[ $? -ne 0 ]]; then
                echo "Failed to show client $client."
            fi
        done
        ;;
    6)
        echo -n "Enter configuration name: "
        read -r config
        if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
            echo "Configuration $config does not exist."
            exit 1
        fi
        show_clients "$config"
        ;;
    7)
        echo -n "Enter configuration name: "
        read -r config
        if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
            echo "Configuration $config does not exist."
            exit 1
        fi
        echo "Available clients in $config:"
        client_count=1
        for client_dir in /etc/amnezia/amneziawg/"$config"/clients/*; do
            if [[ -d "$client_dir" ]]; then
                client_name=$(basename "$client_dir")
                echo "${client_count}. ${client_name}"
                client_count=$((client_count + 1))
            fi
        done
        echo -n "Enter client names separated by space: "
        read -r clients
        for client in $clients; do
            generate_vpn_url "$config" "$client"
            if [[ $? -ne 0 ]]; then
                echo "Failed to generate VPN URL for client $client."
            fi
        done
        ;;
    8)
        echo -n "Enter configuration name: "
        read -r config
        if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
            echo "Configuration $config does not exist."
            exit 1
        fi
        backup_configurations "$config"
        if [[ $? -ne 0 ]]; then
            echo "Failed to backup configuration $config."
        fi
        ;;
    9)
        echo -n "Enter configuration name: "
        read -r config
        if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
            echo "Configuration $config does not exist."
            exit 1
        fi
        restore_from_backup "$config"
        if [[ $? -ne 0 ]]; then
            echo "Failed to restore configuration $config."
        fi
        ;;
    10)
        echo -n "Enter configuration name: "
        read -r config
        if [[ ! -d "/etc/amnezia/amneziawg/$config" ]]; then
            echo "Configuration $config does not exist."
            exit 1
        fi
        uninstall_server "$config"
        if [[ $? -ne 0 ]]; then
            echo "Failed to uninstall configuration $config."
        fi
        ;;
    11)
        confs_info
        ;;
    12)
        echo -n "Enter configuration name: "
        read -r config
        conf_info "$config"
        ;;
    13)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice. Please try again."
        exit 1
        ;;
esac
EOM
if [[ $? -ne 0 ]]; then
    echo "Ошибка при создании утилиты awgen."
    exit 1
fi
log_deploy "Утилита awgen создана."

# Сделать утилиту исполняемой
sudo chmod +x /usr/local/bin/awgen
log_deploy "Утилита awgen сделана исполняемой."

# Добавление /usr/local/bin в PATH, если необходимо
if [[ ":$PATH:" != *":/usr/local/bin:"* ]]; then
    sudo bash -c 'echo "export PATH=\$PATH:/usr/local/bin" > /etc/profile.d/awgen.sh'
    log_deploy "Добавление /usr/local/bin в PATH."
    source /etc/profile.d/awgen.sh
    log_deploy "awgen добавлен в PATH."
else
    log_deploy "Путь /usr/local/bin уже присутствует в PATH."
fi

# Проверка установки
if ! command -v awgen &> /dev/null; then
    log_deploy "awgen не найден в PATH. Проверьте установку."
    echo "awgen не установлен корректно."
    exit 1
else
    log_deploy "awgen успешно установлен и доступен в PATH."
fi

# Установка необходимых зависимостей
log_deploy "Установка необходимых пакетов..."
sudo apt-get update
if sudo apt-get install -y qrencode bc openjdk-17-jre-headless; then
    log_deploy "Необходимые пакеты установлены."
else
    echo "Ошибка при установке зависимостей."
    exit 1
fi

# Установка awgdecoder.jar, если необходимо
if [[ ! -f /usr/local/bin/awgdecoder.jar ]]; then
    AWGDECODER_URL="https://github.com/rakodin/awgdecoder/releases/latest/download/awgdecoder-1.0-SNAPSHOT-run.jar"  # Актуализируйте URL при необходимости
    log_deploy "Скачивание awgdecoder.jar..."
    if sudo wget -O /usr/local/bin/awgdecoder.jar "$AWGDECODER_URL"; then
        sudo chmod +x /usr/local/bin/awgdecoder.jar
        log_deploy "awgdecoder.jar скачан и установлен."
    else
        echo "Ошибка при скачивании awgdecoder.jar."
        exit 1
    fi
else
    log_deploy "awgdecoder.jar уже установлен."
fi

## Настройка cron задач для очистки логов и управления бэкапами
#log_deploy "Настройка cron задач..."
#for config_dir in /etc/amnezia/amneziawg/*; do
#    if [[ -d "$config_dir" ]]; then
#        config=$(basename "$config_dir")
#        # Удаление существующих cron задач для текущей конфигурации
#        (crontab -l 2>/dev/null | grep -v "find /etc/amnezia/amneziawg/logs/") | crontab -
#        (crontab -l 2>/dev/null | grep -v "ls -t /etc/amnezia/amneziawg/backups/") | crontab -
#
#        # Добавление новых cron задач
#        (crontab -l 2>/dev/null; echo "0 0 * * 0 find /etc/amnezia/amneziawg/logs/ -type f -mtime +14 -exec rm {} \;") | crontab -
#        (crontab -l 2>/dev/null; echo "0 0 * * 1 ls -t /etc/amnezia/amneziawg/backups/*.tar | tail -n +5 | xargs rm --") | crontab -
#
#        log_deploy "Cron задачи для конфигурации $config настроены."
#    fi
#done
#log_deploy "Настройка cron задач завершена."

log_deploy "Развертывание утилиты awgen завершено успешно."
# Удаление ловушки после успешного завершения
trap - ERR

echo -e "\e[32mРазвертывание утилиты awgen завершено успешно.\e[0m"
exit 0