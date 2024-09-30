import paramiko
import random
import logging
import sys
import traceback
import ipaddress

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Функция для удаленного выполнения команды через SSH
def execute_remote_command(ssh, command):
    try:
        stdin, stdout, stderr = ssh.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        return output, error, exit_status
    except Exception as e:
        logging.error(f"Исключение при выполнении команды '{command}': {e}")
        return "", str(e), 1  # Возвращаем код ошибки 1


def verify_interface(ssh, interface_name):
    try:
        logging.info(f"Проверка наличия интерфейса {interface_name}.")
        command = f"ip link show {interface_name}"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status == 0 and f"{interface_name}:" in output:
            logging.info(f"Интерфейс {interface_name} обнаружен.")
            return True
        else:
            logging.error(f"Интерфейс {interface_name} не найден: {error}")
            return False
    except Exception as e:
        logging.error(f"Ошибка при проверке интерфейса {interface_name}: {e}")
        return False


def verify_iptables_rules(ssh, interface_name):
    try:
        logging.info("Проверка правил iptables.")
        # Подавляем предупреждения, перенаправляя stderr в /dev/null
        command = f"iptables -S FORWARD 2>/dev/null | grep -- '-A FORWARD -i {interface_name}'"
        output, error, exit_status = execute_remote_command(ssh, command)
        if output.strip():
            logging.info("Правило iptables для FORWARD обнаружено.")
            return True
        else:
            logging.error(f"Правило iptables для FORWARD не найдено. Вывод: {output}, Ошибка: {error}")
            return False
    except Exception as e:
        logging.error(f"Ошибка при проверке правил iptables: {e}")
        return False


def test_ping_interface_ip(ssh, peer_ip):
    try:
        logging.info(f"Проверка пинга собственного IP-адреса {peer_ip}.")
        command = f"ping -c 2 -I {peer_ip} {peer_ip}"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status == 0:
            logging.info(f"Пинг собственного IP {peer_ip} успешен.")
            return True
        else:
            logging.error(f"Пинг собственного IP {peer_ip} не удался: {error}")
            return False
    except Exception as e:
        logging.error(f"Ошибка при выполнении пинга: {e}")
        return False


# Функция для удаленной генерации приватного и публичного ключей
def generate_private_public_keys(ssh):
    logging.info("Генерация приватного и публичного ключей на сервере.")
    private_key, error, exit_status = execute_remote_command(ssh, "awg genkey")
    if exit_status != 0:
        logging.error(f"Ошибка при генерации приватного ключа: {error}")
        return None, None
    public_key, error, exit_status = execute_remote_command(ssh, f"echo {private_key} | awg pubkey")
    if exit_status != 0:
        logging.error(f"Ошибка при генерации публичного ключа: {error}")
        return None, None
    return private_key.strip(), public_key.strip()


# Функция для генерации preshared ключа
def generate_preshared_key(ssh):
    logging.info("Генерация preshared ключа на сервере.")
    preshared_key, error, exit_status = execute_remote_command(ssh, "awg genpsk")
    if exit_status != 0:
        logging.error(f"Ошибка при генерации preshared ключа: {error}")
        return None
    return preshared_key.strip()


# Функция для генерации параметров обфускации
def generate_obfuscation_params():
    logging.info("Генерация параметров обфускации.")
    obfuscation_params = {
        "S1": random.randint(0, 128),
        "S2": random.randint(0, 256),
    }
    h_values = sorted(random.sample(range(0, 1646644383), 4))
    obfuscation_params.update({
        "H1": h_values[0],
        "H2": h_values[1],
        "H3": h_values[2],
        "H4": h_values[3]
    })
    obfuscation_params.update({
        "Jc": random.randint(1, 15),
        "Jmin": random.randint(1, 640),
        "Jmax": random.randint(1, 1280)
    })
    if obfuscation_params["Jmin"] > obfuscation_params["Jmax"]:
        obfuscation_params["Jmin"], obfuscation_params["Jmax"] = obfuscation_params["Jmax"], obfuscation_params["Jmin"]
    return obfuscation_params


# Функция для динамической генерации подсети на основе номера интерфейса
def generate_subnet(interface_index):
    base_subnet = "172.27"
    subnet = f"{base_subnet}.{interface_index}.0/24"
    logging.info(f"Сгенерирована подсеть: {subnet}")
    return subnet


# Функция для проверки существования конфигурационного файла
def check_config_exists(ssh, config_filename):
    try:
        sftp = ssh.open_sftp()
        try:
            sftp.stat(config_filename)
            logging.error(f"Конфигурационный файл {config_filename} уже существует на сервере.")
            return True
        except FileNotFoundError:
            logging.info(f"Конфигурационный файл {config_filename} не существует на сервере. Продолжаем создание.")
            return False
        finally:
            sftp.close()
    except Exception as e:
        logging.error(f"Ошибка при проверке существования файла {config_filename}: {e}")
        return True  # Предполагаем, что файл существует, чтобы избежать перезаписи


# Функция для проверки занятости подсети путем сканирования сети
def check_subnet_in_use(ssh, subnet):
    try:
        logging.info(f"Проверка, что подсеть {subnet} не используется другими конфигурациями.")
        command = "ip addr show"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status != 0:
            logging.error(f"Ошибка при получении списка интерфейсов: {error}")
            return True  # Предполагаем, что подсеть занята, чтобы избежать конфликта

        interfaces_output = output.strip()
        existing_subnets = []
        for line in interfaces_output.split('\n'):
            line = line.strip()
            if line.startswith('inet '):
                inet_line = line.split()
                if len(inet_line) >= 2:
                    inet_address = inet_line[1]  # e.g., '192.168.1.1/24'
                    existing_subnets.append(inet_address)

        new_subnet = ipaddress.IPv4Network(subnet, strict=False)
        for existing_subnet_str in existing_subnets:
            existing_subnet = ipaddress.IPv4Interface(existing_subnet_str).network
            if new_subnet.overlaps(existing_subnet):
                logging.error(f"Подсеть {subnet} конфликтует с существующей подсетью {existing_subnet}")
                return True
        logging.info(f"Подсеть {subnet} не занята. Продолжаем создание.")
        return False
    except Exception as e:
        logging.error(f"Ошибка при проверке занятости подсети {subnet}: {e}")
        return True  # Предполагаем, что подсеть занята, чтобы избежать конфликта


# Функция для проверки занятости порта
def check_port_in_use(ssh, listen_port):
    try:
        logging.info(f"Проверка, что порт {listen_port} не используется другими конфигурациями.")
        command = f"ss -tulpn | grep ':{listen_port} '"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status == 0 and output:
            logging.error(f"Порт {listen_port} уже используется:\n{output}")
            return True
        else:
            logging.info(f"Порт {listen_port} свободен. Продолжаем создание.")
            return False
    except Exception as e:
        logging.error(f"Ошибка при проверке занятости порта {listen_port}: {e}")
        return True  # Предполагаем, что порт занят, чтобы избежать конфликта


# Функция для проверки существования интерфейса
def check_interface_exists(ssh, interface_name):
    try:
        logging.info(f"Проверка, что интерфейс {interface_name} не используется.")
        command = f"ip link show {interface_name}"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status == 0:
            logging.error(f"Интерфейс {interface_name} уже существует.")
            return True
        elif "does not exist" in error:
            logging.info(f"Интерфейс {interface_name} не существует. Продолжаем создание.")
            return False
        else:
            logging.error(f"Неизвестная ошибка при проверке интерфейса {interface_name}: {error}")
            return True  # Предполагаем, что интерфейс существует, чтобы избежать конфликта
    except Exception as e:
        logging.error(f"Ошибка при проверке существования интерфейса {interface_name}: {e}")
        return True  # Предполагаем, что интерфейс существует, чтобы избежать конфликта


# Функция для проверки занятости IP-адреса клиента путем сканирования сети
def check_peer_ip_in_use(ssh, client_ip):
    try:
        logging.info(f"Проверка, что IP-адрес {client_ip} не используется другими конфигурациями.")
        command = "ip addr show"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status != 0:
            logging.error(f"Ошибка при получении списка интерфейсов: {error}")
            return True  # Предполагаем, что IP-адрес занят, чтобы избежать конфликта

        interfaces_output = output.strip()
        existing_ips = []
        for line in interfaces_output.split('\n'):
            line = line.strip()
            if line.startswith('inet '):
                inet_line = line.split()
                if len(inet_line) >= 2:
                    inet_address = inet_line[1].split('/')[0]
                    existing_ips.append(inet_address)

        if client_ip in existing_ips:
            logging.error(f"IP-адрес {client_ip} уже используется на сервере.")
            return True
        else:
            logging.info(f"IP-адрес {client_ip} не занят. Продолжаем создание.")
            return False
    except Exception as e:
        logging.error(f"Ошибка при проверке занятости IP-адреса {client_ip}: {e}")
        return True  # Предполагаем, что IP-адрес занят, чтобы избежать конфликта


# Функция для проверки конфликтов с другими сетями
def check_network_conflict(ssh, subnet):
    try:
        logging.info(f"Проверка конфликтов подсети {subnet} с другими сетями на сервере.")
        command = "ip route show"
        output, error, exit_status = execute_remote_command(ssh, command)
        routes = output.splitlines()
        new_subnet = ipaddress.IPv4Network(subnet, strict=False)
        for route in routes:
            route_parts = route.split()
            if len(route_parts) > 0:
                route_subnet = route_parts[0]
                try:
                    existing_subnet = ipaddress.IPv4Network(route_subnet, strict=False)
                    if new_subnet.overlaps(existing_subnet):
                        logging.error(f"Подсеть {subnet} конфликтует с существующей сетью: {existing_subnet}")
                        return True
                except ValueError:
                    continue
        logging.info(f"Конфликтов подсети {subnet} не обнаружено.")
        return False
    except Exception as e:
        logging.error(f"Ошибка при проверке конфликтов сети {subnet}: {e}")
        return True  # Предполагаем конфликт, чтобы избежать проблем


# Функция для получения интерфейса по умолчанию
def get_default_interface(ssh):
    try:
        command = "ip route | awk '/default/ {print $5; exit}'"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status != 0 or not output.strip():
            logging.error(f"Не удалось определить интерфейс по умолчанию: {error}")
            return None
        default_if = output.strip()
        logging.info(f"Интерфейс по умолчанию: {default_if}")
        return default_if
    except Exception as e:
        logging.error(f"Ошибка при получении интерфейса по умолчанию: {e}")
        return None


# Функция для получения IP-адреса интерфейса
def get_interface_ip(ssh, interface):
    try:
        command = f"ip addr show {interface} | grep 'inet ' | awk '{{print $2}}' | awk -F/ '{{print $1}}' | head -n 1"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status != 0 or not output.strip():
            logging.error(f"Не удалось определить IP-адрес интерфейса {interface}: {error}")
            return None
        interface_ip = output.strip()
        logging.info(f"IP-адрес интерфейса {interface}: {interface_ip}")
        return interface_ip
    except Exception as e:
        logging.error(f"Ошибка при получении IP-адреса интерфейса {interface}: {e}")
        return None


# Функция для создания конфигурационного файла WireGuard для сервера
def generate_server_config(ssh, interface_name, peer_ip, client_ip, client_public_key, server_private_key,
                           preshared_key, allowed_ips, listen_port, obfuscation_params, subnet, default_interface):
    try:
        config = f"""[Interface]
Address = {peer_ip}/24
PrivateKey = {server_private_key}
ListenPort = {listen_port}
Jc = {obfuscation_params['Jc']}
Jmin = {obfuscation_params['Jmin']}
Jmax = {obfuscation_params['Jmax']}
S1 = {obfuscation_params['S1']}
S2 = {obfuscation_params['S2']}
H1 = {obfuscation_params['H1']}
H2 = {obfuscation_params['H2']}
H3 = {obfuscation_params['H3']}
H4 = {obfuscation_params['H4']}

[Peer]
PublicKey = {client_public_key}
PresharedKey = {preshared_key}
AllowedIPs = {client_ip}/32
PersistentKeepAlive = 25
"""
        # Сохраняем конфигурационный файл на сервере
        config_filename = f"/etc/amnezia/amneziawg/{interface_name}/{interface_name}.conf"
        sftp = ssh.open_sftp()
        with sftp.file(config_filename, 'w') as config_file:
            config_file.write(config)
        sftp.chmod(config_filename, 0o600)
        sftp.close()
        logging.info(f"Конфигурационный файл создан на сервере: {config_filename}")

        # Проверка корректности конфигурационного файла
        logging.info("Проверка корректности конфигурационного файла.")
        command = f"awg-quick strip {config_filename} > /dev/null"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status != 0:
            logging.error(f"Ошибка в конфигурационном файле {config_filename}:\n{error}")
            return None, None
        else:
            logging.info("Конфигурационный файл корректен.")
            return config_filename, config
    except Exception as e:
        logging.error(f"Ошибка при создании конфигурационного файла: {e}")
        return None, None


# Функция для создания директории конфигурации
def create_config_directory(ssh, interface_name):
    try:
        config_dir = f"/etc/amnezia/amneziawg/{interface_name}"
        logging.info(f"Создание директории {config_dir}")
        command = f"mkdir -p {config_dir}"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status != 0:
            logging.error(f"Ошибка при создании директории {config_dir}: {error}")
            return False
        else:
            logging.info(f"Директория {config_dir} успешно создана.")
            return True
    except Exception as e:
        logging.error(f"Ошибка при создании директории {config_dir}: {e}")
        return False


# Функция для сохранения ключей в файлы на сервере
def save_keys_to_files(ssh, interface_name, private_key, public_key, preshared_key):
    try:
        sftp = ssh.open_sftp()

        config_dir = f"/etc/amnezia/amneziawg/{interface_name}"
        private_key_file = f"{config_dir}/private.key"
        public_key_file = f"{config_dir}/public.key"
        preshared_key_file = f"{config_dir}/preshared.key"

        # Сохранение приватного ключа
        with sftp.file(private_key_file, 'w') as f:
            f.write(private_key)

        # Сохранение публичного ключа
        with sftp.file(public_key_file, 'w') as f:
            f.write(public_key)

        # Сохранение preshared key
        with sftp.file(preshared_key_file, 'w') as f:
            f.write(preshared_key)

        sftp.chmod(private_key_file, 0o600)
        sftp.close()
        logging.info(f"Ключи сохранены на сервере: {private_key_file}, {public_key_file}, {preshared_key_file}")
        return private_key_file, public_key_file, preshared_key_file
    except Exception as e:
        logging.error(f"Ошибка при сохранении ключей на сервере: {e}")
        return None, None, None


def setup_iptables_rules(ssh, interface_name, subnet, client_ip, allowed_ips, default_interface):
    try:
        logging.info("Настройка правил iptables.")

        commands = [
            f"iptables -A INPUT -i {interface_name} -j ACCEPT",
            f"iptables -A OUTPUT -o {interface_name} -j ACCEPT",
            # Разрешаем установленный и связанный трафик
            f"iptables -A FORWARD -i {interface_name} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"iptables -A FORWARD -o {interface_name} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            # NAT
            f"iptables -t nat -A POSTROUTING -s {subnet} -o {default_interface} -j MASQUERADE"
        ]

        if allowed_ips == ["0.0.0.0/0"]:
            # Разрешаем весь трафик от клиента
            commands.append(f"iptables -A FORWARD -i {interface_name} -j ACCEPT")
            commands.append(f"iptables -A FORWARD -o {interface_name} -j ACCEPT")
        else:
            # Разрешаем трафик только к определённым адресам
            for ip in allowed_ips:
                commands.append(f"iptables -A FORWARD -i {interface_name} -s {client_ip} -d {ip} -j ACCEPT")
            # Блокируем остальной трафик от клиента
            commands.append(f"iptables -A FORWARD -i {interface_name} -s {client_ip} -j DROP")

        for cmd in commands:
            output, error, exit_status = execute_remote_command(ssh, cmd)
            if exit_status != 0:
                logging.error(f"Ошибка при выполнении команды '{cmd}': {error}")
                return False

        logging.info("Правила iptables успешно настроены.")
        return True
    except Exception as e:
        logging.error(f"Ошибка при настройке правил iptables: {e}")
        return False


def cleanup_iptables_rules(ssh, interface_name, subnet, client_ip, allowed_ips, default_interface):
    try:
        logging.info("Удаление правил iptables.")

        commands = [
            f"iptables -D INPUT -i {interface_name} -j ACCEPT",
            f"iptables -D OUTPUT -o {interface_name} -j ACCEPT",
            # Разрешаем установленный и связанный трафик
            f"iptables -D FORWARD -i {interface_name} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"iptables -D FORWARD -o {interface_name} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            # NAT
            f"iptables -t nat -D POSTROUTING -s {subnet} -o {default_interface} -j MASQUERADE"
        ]

        if allowed_ips == ["0.0.0.0/0"]:
            # Удаляем правила для всего трафика
            commands.append(f"iptables -D FORWARD -i {interface_name} -j ACCEPT")
            commands.append(f"iptables -D FORWARD -o {interface_name} -j ACCEPT")
        else:
            # Удаляем правила для определённых адресов
            for ip in allowed_ips:
                commands.append(f"iptables -D FORWARD -i {interface_name} -s {client_ip} -d {ip} -j ACCEPT")
            # Удаляем правило блокировки остального трафика
            commands.append(f"iptables -D FORWARD -i {interface_name} -s {client_ip} -j DROP")

        for cmd in commands:
            output, error, exit_status = execute_remote_command(ssh, cmd)
            if exit_status != 0:
                logging.error(f"Ошибка при выполнении команды '{cmd}': {error}")
                return False

        logging.info("Правила iptables успешно удалены.")
        return True
    except Exception as e:
        logging.error(f"Ошибка при удалении правил iptables: {e}")
        return False


# Функция для создания systemd юнита
def create_systemd_unit(ssh, interface_name, config_file_path, subnet, client_ip, allowed_ips, default_interface):
    try:
        logging.info(f"Создание systemd юнита для awg-quick@{interface_name}.service.")
        unit_content = f"""[Unit]
Description=Amnezia WireGuard Interface {interface_name}
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/awg-quick up {config_file_path}
ExecStartPost=/usr/local/bin/setup_iptables_{interface_name}.sh
ExecStop=/usr/bin/awg-quick down {config_file_path}
ExecStopPost=/usr/local/bin/cleanup_iptables_{interface_name}.sh

[Install]
WantedBy=multi-user.target
"""

        # Сохраняем юнит-файл
        unit_file_path = f"/etc/systemd/system/awg-quick@{interface_name}.service"
        sftp = ssh.open_sftp()
        with sftp.file(unit_file_path, 'w') as unit_file:
            unit_file.write(unit_content)
        sftp.close()

        # Создаем скрипты для настройки и очистки iptables
        setup_script = f"/usr/local/bin/setup_iptables_{interface_name}.sh"
        cleanup_script = f"/usr/local/bin/cleanup_iptables_{interface_name}.sh"

        # Генерируем команды для скриптов
        setup_commands = [
            "#!/bin/bash",
            f"iptables -A INPUT -i {interface_name} -j ACCEPT",
            f"iptables -A OUTPUT -o {interface_name} -j ACCEPT",
            # Разрешаем установленный и связанный трафик
            f"iptables -A FORWARD -i {interface_name} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"iptables -A FORWARD -o {interface_name} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            # NAT
            f"iptables -t nat -A POSTROUTING -s {subnet} -o {default_interface} -j MASQUERADE"
        ]

        cleanup_commands = [
            "#!/bin/bash",
            f"iptables -D INPUT -i {interface_name} -j ACCEPT",
            f"iptables -D OUTPUT -o {interface_name} -j ACCEPT",
            # Разрешаем установленный и связанный трафик
            f"iptables -D FORWARD -i {interface_name} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            f"iptables -D FORWARD -o {interface_name} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            # NAT
            f"iptables -t nat -D POSTROUTING -s {subnet} -o {default_interface} -j MASQUERADE"
        ]

        if allowed_ips == ["0.0.0.0/0"]:
            # Разрешаем весь трафик от клиента
            setup_commands.append(f"iptables -A FORWARD -i {interface_name} -j ACCEPT")
            setup_commands.append(f"iptables -A FORWARD -o {interface_name} -j ACCEPT")

            cleanup_commands.append(f"iptables -D FORWARD -i {interface_name} -j ACCEPT")
            cleanup_commands.append(f"iptables -D FORWARD -o {interface_name} -j ACCEPT")
        else:
            # Разрешаем трафик только к определённым адресам
            for ip in allowed_ips:
                setup_commands.append(f"iptables -A FORWARD -i {interface_name} -s {client_ip} -d {ip} -j ACCEPT")
                cleanup_commands.append(f"iptables -D FORWARD -i {interface_name} -s {client_ip} -d {ip} -j ACCEPT")
            # Блокируем остальной трафик от клиента
            setup_commands.append(f"iptables -A FORWARD -i {interface_name} -s {client_ip} -j DROP")
            cleanup_commands.append(f"iptables -D FORWARD -i {interface_name} -s {client_ip} -j DROP")

        # Создаем скрипты на сервере
        sftp = ssh.open_sftp()
        with sftp.file(setup_script, 'w') as f:
            f.write('\n'.join(setup_commands))
        sftp.chmod(setup_script, 0o755)

        with sftp.file(cleanup_script, 'w') as f:
            f.write('\n'.join(cleanup_commands))
        sftp.chmod(cleanup_script, 0o755)
        sftp.close()

        # Перезагружаем демона systemd
        command = "systemctl daemon-reload"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status != 0:
            logging.error(f"Ошибка при перезагрузке демона systemd: {error}")
            return False

        # Включаем сервис для автозапуска
        command = f"systemctl enable awg-quick@{interface_name}.service"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status != 0:
            logging.error(f"Ошибка при включении сервиса: {error}")
            return False

        logging.info(f"Systemd юнит awg-quick@{interface_name}.service создан и включен.")
        return True
    except Exception as e:
        logging.error(f"Ошибка при создании systemd юнита: {e}")
        return False


# Функция для запуска сервиса
def start_service(ssh, interface_name):
    try:
        logging.info(f"Запуск сервиса awg-quick@{interface_name}.service.")
        command = f"systemctl start awg-quick@{interface_name}.service"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status != 0:
            logging.error(f"Ошибка при запуске сервиса: {error}")
            return False
        return True
    except Exception as e:
        logging.error(f"Ошибка при запуске сервиса awg-quick@{interface_name}.service: {e}")
        return False


# Функция для проверки статуса сервиса
def check_service_status(ssh, interface_name):
    try:
        command = f"systemctl is-active awg-quick@{interface_name}.service"
        output, error, exit_status = execute_remote_command(ssh, command)
        if exit_status == 0:
            return output.strip()
        else:
            logging.error(f"Ошибка при проверке статуса сервиса: {error}")
            return "unknown"
    except Exception as e:
        logging.error(f"Ошибка при проверке статуса сервиса awg-quick@{interface_name}.service: {e}")
        return "unknown"


from settings import SSH_CONNECTIONS


# Основная функция
def main(server_ini_key: str, interface_index: int, allowed_ips: list, listen_port: int):
    ssh = None
    try:
        # Ключи от сервера для SSH
        server_ssh_keys = SSH_CONNECTIONS[server_ini_key]

        # Данные конфигурации сервера
        server = server_ssh_keys["HOST"]
        ssh_port = server_ssh_keys["PORT"]
        username = server_ssh_keys["USER"]
        password = server_ssh_keys["PASSWORD"]

        # Проверка доступности сервера и установление SSH-соединения
        logging.info(f"Попытка подключения к серверу {server} по SSH.")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server, port=ssh_port, username=username, password=password, timeout=10)
        logging.info(f"Подключение к серверу {server} по SSH установлено.")

        # Создаем директорию, если её нет
        output, error, exit_status = execute_remote_command(ssh, "mkdir -p /etc/amnezia/amneziawg/")
        if exit_status != 0:
            logging.error(f"Ошибка при создании директории: {error}")
            return
        logging.info("Проверка или создание директории /etc/amnezia/amneziawg/.")

        interface_name = f"awg{interface_index}"
        peer_ip = f"172.27.{interface_index}.1"  # IP сервера в этой подсети
        client_ip = f"172.27.{interface_index}.2"  # IP клиента в этой подсети
        subnet = generate_subnet(interface_index)

        # Проверка существования конфигурационного файла
        config_filename = f"/etc/amnezia/amneziawg/{interface_name}/{interface_name}.conf"
        if check_config_exists(ssh, config_filename):
            logging.error(f"Конфигурация с именем {interface_name} уже существует. Отмена выполнения.")
            return

        # Проверка занятости подсети
        if check_subnet_in_use(ssh, subnet):
            logging.error(f"Подсеть {subnet} уже занята. Отмена выполнения.")
            return

        # Проверка конфликтов с другими сетями
        if check_network_conflict(ssh, subnet):
            logging.error(f"Подсеть {subnet} конфликтует с существующими сетями. Отмена выполнения.")
            return

        # Проверка занятости порта
        if check_port_in_use(ssh, listen_port):
            logging.error(f"Порт {listen_port} уже занят. Отмена выполнения.")
            return

        # Проверка занятости интерфейса
        if check_interface_exists(ssh, interface_name):
            logging.error(f"Интерфейс {interface_name} уже существует. Отмена выполнения.")
            return

        # Проверка занятости IP-адреса клиента
        if check_peer_ip_in_use(ssh, client_ip):
            logging.error(f"IP-адрес клиента {client_ip} уже используется. Отмена выполнения.")
            return

        # Создание директории для конфигурации
        if not create_config_directory(ssh, interface_name):
            logging.error(f"Не удалось создать директорию для конфигурации {interface_name}. Отмена выполнения.")
            return

        # Генерация ключей на сервере
        server_private_key, server_public_key = generate_private_public_keys(ssh)
        client_private_key, client_public_key = generate_private_public_keys(ssh)  # Эти ключи будут у клиента
        preshared_key = generate_preshared_key(ssh)

        # Сохранение ключей на сервере
        save_keys_to_files(ssh, interface_name, server_private_key, server_public_key, preshared_key)

        # Генерация уникальных параметров обфускации
        obfuscation_params = generate_obfuscation_params()

        # Получение интерфейса по умолчанию и его IP
        default_interface = get_default_interface(ssh)
        if not default_interface:
            logging.error("Не удалось определить интерфейс по умолчанию. Отмена выполнения.")
            return

        default_ip = get_interface_ip(ssh, default_interface)
        if not default_ip:
            logging.error(f"Не удалось определить IP-адрес интерфейса {default_interface}. Отмена выполнения.")
            return

        # Генерация конфигурационного файла на сервере
        config_filename, config_content = generate_server_config(
            ssh, interface_name, peer_ip, client_ip, client_public_key, server_private_key,
            preshared_key, allowed_ips, listen_port, obfuscation_params, subnet, default_interface
        )

        if not config_filename:
            logging.error("Ошибка при создании конфигурационного файла. Отмена выполнения.")
            return

        # Создание systemd юнита
        if not create_systemd_unit(ssh, interface_name, config_filename, subnet, client_ip, allowed_ips,
                                   default_interface):
            logging.error("Ошибка при создании systemd юнита. Отмена выполнения.")
            return

        # Запуск сервиса awg-quick
        start_service(ssh, interface_name)

        # Проверка статуса сервиса
        status = check_service_status(ssh, interface_name)

        if status == 'active':
            logging.info(f"Сервис awg-quick@{interface_name}.service успешно запущен.")

            # Проверка наличия интерфейса
            if verify_interface(ssh, interface_name):
                logging.info(f"Интерфейс {interface_name} успешно создан.")
            else:
                logging.error(f"Интерфейс {interface_name} не обнаружен. Проверьте настройки.")

            # Проверка правил iptables
            if verify_iptables_rules(ssh, interface_name):
                logging.info("Правила iptables успешно настроены.")
            else:
                logging.error("Проблемы с настройкой правил iptables. Проверьте конфигурацию.")
        else:
            logging.error(
                f"Сервис awg-quick@{interface_name}.service не запущен. Проверьте логи для детальной информации.")
            # Вывод логов сервиса для диагностики
            output, error, exit_status = execute_remote_command(
                ssh,
                f"journalctl -u awg-quick@{interface_name}.service --no-pager"
            )
            if output.strip():
                logging.error(f"Логи сервиса:\n{output}")
            if error.strip():
                logging.error(f"Ошибки при получении логов:\n{error}")

        # Проверка пинга собственного IP
        if test_ping_interface_ip(ssh, peer_ip):
            logging.info("Туннель настроен правильно.")
        else:
            logging.error("Проблемы с настройкой туннеля. Проверьте конфигурацию.")

        # Возвращаем данные для дальнейшего использования
        return {
            'config_filename': config_filename,
            'config_content': config_content,
            'client_private_key': client_private_key,
            'client_public_key': client_public_key,
            'preshared_key': preshared_key,
            'obfuscation_params': obfuscation_params,
            'subnet': subnet,
            'peer_ip': peer_ip,
            'client_ip': client_ip,
            'listen_port': listen_port,
            'allowed_ips': allowed_ips
        }
    except paramiko.SSHException as e:
        logging.error(f"SSH ошибка при подключении к серверу {server}: {e}")
    except Exception as e:
        logging.error(f"Общая ошибка: {e}")
        traceback.print_exc()
    finally:
        if ssh:
            ssh.close()
            logging.info("SSH соединение закрыто.")


if __name__ == "__main__":
    server_ini_key = 'ssh-connect-kvm4-eu-vilnus'
    interface_index = 11
    allowed_ips = ["0.0.0.0/0"]
    listen_port = 30011


    result = main(server_ini_key, interface_index, allowed_ips, listen_port)

    # Здесь вы можете использовать данные из result для дальнейшей обработки
    # Например, сохранить данные в базу данных или сгенерировать клиентскую конфигурацию
