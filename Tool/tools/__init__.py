import os
import configparser

config_file_path = os.path.join(os.path.dirname(__file__), '..', 'config.ini')

config = configparser.ConfigParser()
config.read(config_file_path)

def get_config():
    return config


def safe_get(value, default=""):
    return value if value is not None else default