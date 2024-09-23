#!/bin/bash

echo "Скрипт для установки Amnezia-WG на сервер с Linux (Debian или Ubuntu)"

# Проверка на выполнение с правами root
if [[ $EUID -ne 0 ]]; then
   echo -e "\e[31mЭтот скрипт должен быть запущен с правами root\e[0m"
   exit 1
fi

# Функция для логирования. Создание директории для логов, если она не существует
log() {
    local log_dir="/etc/amnezia/amneziawg/logs"
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir" || { echo "Не удалось создать директорию логов: $log_dir"; exit 1; }
    fi
    local log_file="${log_dir}/$(date +'%d.%m.%Y').log"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >> "$log_file"
}

# Статичный прогресс для этапов установки
log_stage() {
    local stage_message="$1"
    echo -ne "\r\e[32m$stage_message...\e[0m"
    log "$stage_message"
}

# Установка sudo, если он еще не установлен
if ! command -v sudo &> /dev/null; then
    log_stage "Установка sudo"
    apt update && apt install -y sudo || { echo "Не удалось установить sudo"; log "Ошибка установки sudo"; exit 1; }
    log "sudo установлен."
    echo -e "\r\e[32msudo установлен.\e[0m"
fi

# Установка bc, если он еще не установлен
if ! command -v bc &> /dev/null; then
    log_stage "Установка bc"
    apt update && apt install -y bc || { echo "Не удалось установить bc"; log "Ошибка установки bc"; exit 1; }
    log "bc установлен."
    echo -e "\r\e[32mbc установлен.\e[0m"
fi

# Создание директорий для логов и бэкапов, если они не существуют
log_stage "Создание директорий для логов и бэкапов"
sudo mkdir -p /etc/amnezia/amneziawg/logs || { echo "Не удалось создать директорию для логов"; log "Ошибка создания директории логов"; exit 1; }
sudo mkdir -p /etc/amnezia/amneziawg/backups || { echo "Не удалось создать директорию для бэкапов"; log "Ошибка создания директории бэкапов"; exit 1; }
log "Директории для логов и бэкапов созданы."
echo -e "\r\e[32mДиректории для логов и бэкапов созданы.\e[0m"

# Обновление системы
log_stage "Обновление системы"
if ! apt update && apt upgrade -y > /dev/null 2>&1; then
    log "Не удалось обновить систему"
    echo "Не удалось обновить систему"
    exit 1
fi
log "Система обновлена."
echo -e "\r\e[32mСистема обновлена.\e[0m"

# Установка необходимых пакетов
log_stage "Установка необходимых пакетов"
if ! apt install -y iptables software-properties-common python3-launchpadlib gnupg2 linux-headers-$(uname -r) qrencode bc > /dev/null 2>&1; then
    log "Не удалось установить необходимые пакеты"
    echo "Не удалось установить необходимые пакеты"
    exit 1
fi
log "Необходимые пакеты установлены."
echo -e "\r\e[32mНеобходимые пакеты установлены.\e[0m"

# Добавление репозитория Amnezia
log_stage "Добавление репозитория Amnezia"
if ! sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828 > /dev/null 2>&1; then
    log "Ошибка добавления GPG ключа Amnezia"
    echo "Ошибка добавления GPG ключа Amnezia"
    exit 1
fi
if ! echo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | sudo tee -a /etc/apt/sources.list > /dev/null; then
    log "Ошибка добавления репозитория Amnezia"
    echo "Ошибка добавления репозитория Amnezia"
    exit 1
fi
if ! echo "deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" | sudo tee -a /etc/apt/sources.list > /dev/null; then
    log "Ошибка добавления исходного кода репозитория Amnezia"
    echo "Ошибка добавления исходного кода репозитория Amnezia"
    exit 1
fi
log "Репозиторий Amnezia добавлен."
echo -e "\r\e[32mРепозиторий Amnezia добавлен.\e[0m"

# Обновление списка пакетов и установка Amnezia-WG
log_stage "Обновление списка пакетов и установка Amnezia-WG"
if ! sudo apt-get update > /dev/null 2>&1; then
    log "Ошибка обновления списка пакетов"
    echo "Ошибка обновления списка пакетов"
    exit 1
fi
if ! sudo apt-get install -y amneziawg > /dev/null 2>&1; then
    log "Ошибка установки Amnezia-WG"
    echo "Ошибка установки Amnezia-WG"
    exit 1
fi
log "Amnezia-WG установлена."
echo -e "\r\e[32mAmnezia-WG установлена.\e[0m"

# Завершение установки
echo -e "\e[32mУстановка Amnezia-WG успешно завершена.\e[0m"
log "Установка Amnezia-WG завершена."