from os import path

import mysql.connector as mc
from utils.utils import get_root_dir


def _read_file(path: str) -> str:
    with open(path) as f:
        content = f.read()
    return content.strip()


root_dir = get_root_dir()
host = _read_file(path.join(root_dir, "webappConfig/mysql_host.txt"))
user = _read_file(path.join(root_dir, "webappConfig/mysql_username.txt"))
password = _read_file(path.join(root_dir, "webappConfig/mysql_password.txt"))


def get_all():
    sql = "select * from webapp"
    config = {
        'user': user,
        'password': password,
        'host': host,
        'port': '3306',
        'database': 'csye6225'
    }
    con = mc.connect(**config)

    cursor = con.cursor(buffered=True)
    try:
        cursor.execute(sql)
        result = cursor.fetchall()
        for each in result:
            print(each)
        con.close()

    except Exception:
        return None


if __name__ == '__main__':
    get_all()
