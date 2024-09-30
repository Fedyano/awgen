import os
import configparser
import logging

# Настройка логирования
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Определение окружения (production, development, default.ini)
env = os.getenv('APP_ENV', 'default').lower()

# Определение пути к файлу конфигурации в зависимости от окружения
# если здесь есть файл, а в папке его нет то значит надо у кого-то найти
config_file_map = {
    'production': 'config/production.ini',
    'development': 'config/development.ini',
    'default': 'config/default.ini',
    'local-master': 'config/local-master.ini'
}

# Проверка наличия файлов конфигурации
available_files = []
for key, path in config_file_map.items():
    if os.path.exists(path):
        available_files.append(path)

# Попытка загрузки файла конфигурации для текущего окружения
config_file = config_file_map.get(env, 'config/default.ini')
if not os.path.exists(config_file):
    print(f"Warning: Configuration file for '{env}' environment not found. Using default configuration.")
    logger.warning(f"Configuration file for '{env}' environment not found. Using default configuration.")
    config_file = config_file_map['default']

# Выводим информацию о доступных конфигурационных файлах
logger.info(f"Available configuration files: {available_files}")

config_file = config_file_map.get(env, "config/default.ini")
print(f"Using configuration file: {config_file}")

# Чтение конфигурации из выбранного файла .ini
config = configparser.ConfigParser()
config.read(config_file)


def get_config_param(env_var, ini_section, ini_key, default=None):
    """Функция, возвращающая параметр, сначала проверяя переменные окружения, затем конфигурационный файл .ini."""
    return os.getenv(env_var) or config.get(ini_section, ini_key, fallback=default)


def get_servers_connections(ini_section):
    return config.get(ini_section)


# Параметры базы данных
DB_USER = get_config_param('DB_USER', 'database', 'DB_USER')
DB_PASSWORD = get_config_param('DB_PASSWORD', 'database', 'DB_PASSWORD')
DB_HOST = get_config_param('DB_HOST', 'database', 'DB_HOST')
DB_PORT = get_config_param('DB_PORT', 'database', 'DB_PORT')
DB_NAME = get_config_param('DB_NAME', 'database', 'DB_NAME')
SSL_MODE = get_config_param('SSL_MODE', 'database', 'SSL_MODE')

# Подключения серверов
# получить все серверные секции

# Инициализируем пустой словарь для хранения данных
SSH_CONNECTIONS = {}

# Проходим по всем секциям в конфигурации
for section in config.sections():
    # Проверяем, содержит ли имя секции 'ssh-connect-'
    if section.startswith('ssh-connect-'):
        # Извлекаем данные из каждой секции и добавляем в словарь
        SSH_CONNECTIONS[section] = {
            'HOST': config.get(section, 'HOST'),
            'PORT': config.get(section, 'PORT'),
            'USER': config.get(section, 'USER'),
            'PASSWORD': config.get(section, 'PASSWORD')
        }