#!/bin/bash

# Проверка на выполнение с правами root
if [[ $EUID -ne 0 ]]; then
   echo "Этот скрипт нужно запускать с правами root"
   exit 1
fi

# Функция для логирования
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# Установка sudo, если он еще не установлен
log "Проверка наличия sudo..."
if ! command -v sudo &> /dev/null; then
    log "Установка sudo и обновление системы..."
    apt update && apt upgrade -y || { log "Не удалось обновить систему"; exit 1; }
    apt install -y sudo linux-image-generic || { log "Не удалось установить sudo или linux-image-generic"; exit 1; }
else
    log "sudo уже установлен"
fi

# Обновление системы
log "Обновление системы..."
apt update && apt upgrade -y && apt autoremove -y || { log "Не удалось обновить систему"; exit 1; }

# Включение всех репозиториев пакетов с исходными кодами
log "Включение всех репозиториев с исходными кодами..."
cd /etc/apt/ || { log "Не удалось перейти в /etc/apt/"; exit 1; }

# Создание резервной копии файла sources.list
log "Создание резервной копии sources.list"
cp sources.list sources.list.backup || { log "Не удалось создать резервную копию sources.list"; exit 1; }

# Включение исходных репозиториев
log "Обновление sources.list для включения исходных репозиториев..."
sed "s/# deb-src/deb-src/" sources.list.backup > sources.list || { log "Не удалось обновить sources.list"; exit 1; }

log "Установка сurl..."
sudo apt install curl

# Предложение перезагрузки
log "Обновление завершено. Рекомендуется перезагрузить сервер."

read -p "Вы хотите перезагрузить сервер сейчас? (y/n): " choice
if [[ "$choice" == [Yy]* ]]; then
    log "Перезагрузка сервера..."
    reboot
else
    log "Перезагрузка отменена пользователем."
fi