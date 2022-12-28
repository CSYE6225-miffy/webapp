import json
import os
import typing as t

from utils.constants import APP_CONFIG_PATH


def my_io():
    return 1


def get_root_dir() -> str:
    pwd = os.getcwd()
    path_parts = pwd.rpartition('webapp')
    root_dir = os.path.join(*path_parts[:-1])
    return root_dir


def load_app_config() -> t.Dict[str, t.Any]:
    with open(os.path.join(get_root_dir(), APP_CONFIG_PATH)) as f:
        app_config = json.load(f)
    return app_config
