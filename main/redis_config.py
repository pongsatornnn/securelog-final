import os
from dotenv import load_dotenv

load_dotenv()

REDIS_CONFIG = {
    'host': os.getenv('REDIS_HOST'),
    'port': int(os.getenv('REDIS_PORT', 6380)),
    'ssl': True,

    'ssl_certfile': os.getenv('REDIS_CERT'),
    'ssl_keyfile': os.getenv('REDIS_KEY'),
    'ssl_ca_certs': os.getenv('REDIS_CA'),

    'username': os.getenv('REDIS_USER'),
    'password': os.getenv('REDIS_PASS'),

    'ssl_check_hostname': True
}
