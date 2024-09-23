#!/bin/bash

echo "Скрипт для оптимизации TCP (+BBR) и UDP на сервере Linux с использованием Debian или Ubuntu"

# Проверка на выполнение с правами root
# Если скрипт не запущен с root правами, выводим сообщение и прекращаем выполнение
if [[ $EUID -ne 0 ]]; then
   echo -e "\e[31mЭтот скрипт должен быть запущен с правами root\e[0m"
   exit 1
fi

# Проверка на наличие утилиты bc. Если она отсутствует, скрипт устанавливает её через apt
# bc используется для работы с вещественными числами (нужно для прогресс-бара)
if ! command -v bc &> /dev/null; then
    apt update && apt install -y bc || { echo "Не удалось установить bc"; exit 1; }
fi

# Функция для логирования
# Создаёт директорию для логов, если она не существует, и записывает в лог текущие события
log() {
    local log_dir="/var/log/net_optimization"  # Указываем директорию для логов
    if [ ! -d "$log_dir" ]; then
        mkdir -p "$log_dir" || { echo "Не удалось создать директорию логов: $log_dir"; exit 1; }
    fi
    local log_file="${log_dir}/$(date +'%d.%m.%Y').log"  # Лог-файл на основе текущей даты
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >> "$log_file"
}

# Обновление и обновление системы
# Выполняем обновление списка пакетов и обновление системы. Логируем действия
log "Обновление системы..."

if ! apt update && apt upgrade -y; then
    log "Не удалось обновить систему"
    echo "Не удалось обновить систему"
    exit 1
fi
wait

# Функция для удаления существующих настроек в указанном файле
# Используется для очистки файла от старых или ненужных записей перед добавлением новых
remove_existing_settings() {
    local file="$1"
    shift
    for setting in "$@"; do
        if sed -i "/^\s*$setting\b/d" "$file"; then  # Удаляем строки, содержащие настройку
            log "Удалена существующая настройка: $setting из $file"
        else
            log "Не удалось удалить настройку: $setting из $file"
        fi
    done
}

# Функция для добавления или обновления настроек в указанном файле
# Она проверяет, есть ли уже эта настройка в файле. Если есть — обновляет, если нет — добавляет
add_or_update_setting() {
    local file="$1"
    local setting="$2"
    local key=$(echo "$setting" | cut -d '=' -f 1 | xargs)  # Извлекаем ключ (имя параметра)
    local value=$(echo "$setting" | cut -d '=' -f 2- | xargs)  # Извлекаем значение параметра

    # Если параметр уже существует, обновляем его, иначе добавляем в конец файла
    if grep -qE "^\s*$key\s*=" "$file"; then
        if sed -i "s|^\s*$key\s*=.*|$key = $value|" "$file"; then
            log "Обновлена настройка: $key в $file"
        else
            log "Не удалось обновить настройку: $key в $file"
        fi
    else
        if echo "$key = $value" >> "$file"; then
            log "Добавлена настройка: $setting в $file"
        else
            log "Не удалось добавить настройку: $setting в $file"
        fi
    fi
}

# Создание резервных копий конфигурационных файлов
# Создаём бэкапы перед внесением изменений, чтобы можно было вернуть систему в исходное состояние
log "Создание резервных копий конфигурационных файлов"
cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%F_%T)
cp /etc/security/limits.conf /etc/security/limits.conf.backup.$(date +%F_%T)

# Включение форвардинга
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/00-amnezia.conf
sudo sysctl -p /etc/sysctl.conf

# Настройка лимитов на количество открытых файлов
# Устанавливаем лимиты на количество одновременно открытых файлов для всех пользователей и root
log "Настройка лимитов файлов в /etc/security/limits.conf"
remove_existing_settings /etc/security/limits.conf "\*" "root"
add_or_update_setting /etc/security/limits.conf "* soft nofile 51200"
add_or_update_setting /etc/security/limits.conf "* hard nofile 51200"
add_or_update_setting /etc/security/limits.conf "root soft nofile 51200"
add_or_update_setting /etc/security/limits.conf "root hard nofile 51200"

# Функция для проверки и настройки RPS (Receive Packet Steering)
setup_rps() {
    local interface="$1"

    # Проверка наличия интерфейса
    if [ ! -d "/sys/class/net/$interface" ]; then
        echo "Интерфейс $interface не найден. Пропуск настройки RPS."
        return 1
    fi

    # Определение количества процессорных ядер
    local num_cpus
    num_cpus=$(nproc)
    log "ОБНАРУЖЕНО ПРОЦЕССОРОВ: $num_cpus"

    # Формирование битовой маски для использования всех ядер
    local rps_mask
    rps_mask=$(printf "%x" $((2**num_cpus - 1)))

    # Проверка поддержки RPS для интерфейса
    if [ -e "/sys/class/net/$interface/queues/rx-0/rps_cpus" ]; then
        echo "Настройка RPS на интерфейсе $interface с маской $rps_mask"
        echo "$rps_mask" > "/sys/class/net/$interface/queues/rx-0/rps_cpus"

        # Проверка успешности применения RPS
        local applied_rps
        applied_rps=$(cat /sys/class/net/$interface/queues/rx-0/rps_cpus)
        if [ "$applied_rps" = "$rps_mask" ]; then
            log "RPS успешно настроен для интерфейса $interface"
            echo "RPS успешно настроен для интерфейса $interface"
        else
            log "Ошибка применения RPS для интерфейса $interface"
            echo "Ошибка применения RPS для интерфейса $interface"
            return 1
        fi
    else
        log "RPS не поддерживается на интерфейсе $interface"
        echo "RPS не поддерживается на интерфейсе $interface"
        return 1
    fi

    # Автозагрузка RPS при старте системы
    if grep -q "echo $rps_mask > /sys/class/net/$interface/queues/rx-0/rps_cpus" /etc/rc.local; then
        log "Настройка RPS уже добавлена в /etc/rc.local"
    else
        log "Добавление настройки RPS в /etc/rc.local"
        sed -i '/exit 0/d' /etc/rc.local
        echo "echo $rps_mask > /sys/class/net/$interface/queues/rx-0/rps_cpus" >> /etc/rc.local
        echo "exit 0" >> /etc/rc.local
    fi
}

modprobe nf_conntrack
echo "nf_conntrack" >> /etc/modules

# Проверка и настройка RPS для интерфейса eth0
log "Проверка и настройка RPS для интерфейса eth0"
setup_rps "eth0"

# Установка ulimit
# Применяем лимиты на количество файлов для текущей сессии
if ! ulimit -n 51200; then
    log "Не удалось установить ulimit"
    echo "Не удалось установить ulimit"
    exit 1
fi

# Добавление настроек TCP и UDP в /etc/sysctl.conf
# Здесь мы добавляем различные параметры, которые влияют на работу TCP и UDP стека, включая BBR и оптимизацию буферов
log "Добавление настроек TCP и UDP в /etc/sysctl.conf"
sysctl_settings=(
    "fs.file-max=51200"  # Максимальное количество открытых файлов для всей системы
    "net.core.rmem_max=67108864"  # Максимальный размер буфера для приёма данных
    "net.core.wmem_max=67108864"  # Максимальный размер буфера для отправки данных
    "net.core.netdev_max_backlog=250000"  # Максимальный размер очереди пакетов для интерфейса
    "net.core.somaxconn=4096"  # Максимальное количество подключений в очереди
    "net.core.default_qdisc=fq"  # Планировщик очереди для уменьшения задержек
    "net.ipv4.tcp_syncookies=1"  # Защита от SYN-флуд атак
    "net.ipv4.tcp_tw_reuse=1"  # Повторное использование сокетов в состоянии TIME_WAIT
    "net.ipv4.tcp_fin_timeout=30"  # Таймаут для закрытия TCP соединений
    "net.ipv4.tcp_keepalive_time=1200"  # Время ожидания перед началом отправки keepalive-пакетов
    "net.ipv4.tcp_keepalive_probes=5"  # Количество keepalive-пакетов до завершения соединения
    "net.ipv4.tcp_keepalive_intvl=30"  # Интервал между keepalive-пакетами
    "net.ipv4.tcp_max_syn_backlog=8192"  # Максимальное количество подключений в очереди SYN
    "net.ipv4.ip_local_port_range=10000 65000"  # Диапазон локальных портов для исходящих соединений
    "net.ipv4.tcp_slow_start_after_idle=0"  # Отключение медленного старта после простоя соединения
    "net.ipv4.tcp_max_tw_buckets=5000"  # Максимальное количество сокетов в состоянии TIME_WAIT
    "net.ipv4.tcp_fastopen=3"  # Включение TCP Fast Open для клиентской и серверной стороны
    "net.ipv4.udp_mem=25600 51200 102400"  # Память для UDP соединений: минимальная, при давлении и максимальная
    "net.ipv4.tcp_mem=25600 51200 102400"  # Память для TCP соединений: минимальная, при давлении и максимальная
    "net.ipv4.tcp_rmem=4096 87380 67108864"  # Размеры буферов для приёма TCP пакетов: min, default, max
    "net.ipv4.tcp_wmem=4096 65536 67108864"  # Размеры буферов для отправки TCP пакетов: min, default, max
    "net.ipv4.tcp_mtu_probing=1"  # Включение MTU probing для предотвращения фрагментации
    "net.ipv4.tcp_congestion_control=bbr"  # Включение BBR как алгоритма управления перегрузкой
    "net.ipv4.tcp_window_scaling=1"  # Включение масштабирования окна TCP
    "net.core.rmem_default=26214400"  # Дефолтный размер буфера для приёма данных
    "net.core.wmem_default=26214400"  # Дефолтный размер буфера для отправки данных
    "net.ipv4.udp_rmem_min=16384"  # Минимальный размер буфера для приёма UDP данных
    "net.ipv4.udp_wmem_min=16384"  # Минимальный размер буфера для отправки UDP данных
    "net.ipv4.conf.all.rp_filter=1"  # Включение проверки обратного пути (защита от спуфинга)
    "net.ipv4.conf.all.accept_redirects=0"  # Отключение ICMP Redirects
    "net.ipv6.conf.all.accept_redirects=0"  # Отключение ICMP Redirects для IPv6
    "net.ipv4.conf.all.send_redirects=0"  # Отключение отправки ICMP Redirects
    "net.netfilter.nf_conntrack_max=1000000"  # Увеличение количества отслеживаемых соединений
    "net.netfilter.nf_conntrack_tcp_timeout_established=1200"  # Уменьшение таймаута для отслеживания TCP соединений
    "net.core.rps_sock_flow_entries=32768"  # Включение многопоточности для обработки пакетов
)

# Применение всех настроек sysctl
for setting in "${sysctl_settings[@]}"; do
    add_or_update_setting /etc/sysctl.conf "$setting"
done

# Применение изменений в параметрах ядра (sysctl)
# sysctl -p загружает все изменения из /etc/sysctl.conf
log "Применение настроек sysctl"
if ! sysctl -p; then
    log "Не удалось применить настройки sysctl"
    echo "Не удалось применить настройки sysctl"
    exit 1
fi

# Установка пакетов для оптимизации
# Устанавливаем irqbalance и ethtool, необходимые для балансировки прерываний и включения аппаратного оффлоудинга
log "Установка пакетов для оптимизации (irqbalance, ethtool)"

if ! apt install -y irqbalance ethtool; then
    log "Не удалось установить irqbalance и ethtool"
    echo "Не удалось установить irqbalance и ethtool"
    exit 1
fi
wait

# Включение и запуск irqbalance для балансировки прерываний между ядрами процессора
log "Включение и запуск irqbalance"
if ! systemctl enable irqbalance || ! systemctl start irqbalance; then
    log "Не удалось запустить irqbalance"
    echo "Не удалось запустить irqbalance"
    exit 1
fi

# Включение аппаратного оффлоудинга (GRO, TSO)
# Это улучшает производительность сетевого стека, если сетевой интерфейс поддерживает оффлоудинг
log "Включение аппаратного оффлоудинга (GRO, TSO)"
DEFAULT_INTERFACE=$(ip route | grep '^default' | awk '{print $5}')  # Определение интерфейса по умолчанию
if [ -n "$DEFAULT_INTERFACE" ]; then
    if ! ethtool -K "$DEFAULT_INTERFACE" gro on || ! ethtool -K "$DEFAULT_INTERFACE" tso on; then
        log "Не удалось включить аппаратный оффлоудинг на интерфейсе $DEFAULT_INTERFACE"
        echo "Не удалось включить аппаратный оффлоудинг на интерфейсе $DEFAULT_INTERFACE"
        exit 1
    fi
else
    log "Не удалось определить интерфейс по умолчанию"
    echo "Не удалось определить интерфейс по умолчанию"
    exit 1
fi

# Завершение оптимизации
# Выводим сообщение о завершении и записываем в лог
echo -e "\e[32mОптимизация TCP и UDP успешно завершена.\e[0m"
log "Оптимизация TCP и UDP применена."