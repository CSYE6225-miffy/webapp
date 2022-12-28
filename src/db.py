import typing as t
from os import path
from textwrap import dedent

import mysql.connector as mc

from utils.utils import get_root_dir


def _read_file(path: str) -> str:
    with open(path) as f:
        content = f.read()
    return content.strip()


def load_db_credentials() -> t.Tuple[str, str, str]:
    root_dir = get_root_dir()
    host = _read_file(path.join(root_dir, "webappConfig/mysql_host.txt"))
    user = _read_file(path.join(root_dir, "webappConfig/mysql_username.txt"))
    password = _read_file(path.join(root_dir, "webappConfig/mysql_password.txt"))
    return host, user, password


class DB:
    def __init__(self, host: str, user: str, password: str) -> None:
        self.host = host
        self.user = user
        self.password = password

    def connect_mysql(self, should_select_db: bool = True):
        config = {
            'user': self.user,
            'password': self.password,
            'host': self.host,
            'port': '3306',
            'ssl_ca': '/home/ubuntu/webapp/us-west-2-bundle.pem',
            'ssl_verify_identity': True
        }
        if should_select_db:
            config['database'] = 'csye6225'
        con = mc.connect(**config)
        return con

    def _sql_query(self, *queries, should_select_db: bool = True) -> None:
        con = self.connect_mysql(should_select_db)
        try:
            cursor = con.cursor(buffered=True)
            for query in queries:
                cursor.execute(query)
            con.commit()
        finally:
            con.close()

    def setup_db(self):
        try:
            self._sql_query('CREATE DATABASE IF NOT EXISTS csye6225;', should_select_db=False)
            self._sql_query(
                dedent(
                    """
                    CREATE TABLE IF NOT EXISTS webapp 
                    (
                        id varchar(50) not null PRIMARY KEY,
                        username varchar(50) not null UNIQUE,
                        password varchar(100) not null,
                        first_name varchar(30) not null,
                        last_name varchar(30) not null,
                        account_created datetime not null,
                        account_updated datetime not null,
                        verified boolean default FALSE null
                    );
                    """
                )
            )

            self._sql_query(
                dedent(
                    """
                    CREATE TABLE IF NOT EXISTS documents 
                    (
                        uid varchar(50) not null,
                        doc_id varchar(50) not null,
                        filename varchar(50) not null,
                        s3_bucket_path varchar(200) not null,
                        date_created date default null null,
                        PRIMARY KEY(uid, doc_id)
                    );
                    """
                )
            )
            return True
        except Exception as e:
            raise e
            return False

    def delete_db_table(self):
        con = self.connect_mysql()
        cursor = con.cursor(buffered=True)
        try:
            sql = "drop table webapp"
            cursor.execute(sql)
            con.commit()
            con.close()
            return True
        except Exception:
            return False

    def execute_and_get_result(self, sql) -> t.Dict[str, t.Any]:
        con = self.connect_mysql()
        try:
            cursor = con.cursor(buffered=True)
            cursor.execute(sql)
            result = cursor.fetchall()
        finally:
            con.close()
        return [dict(zip(cursor.column_names, x)) for x in result]

    def execute(self, sql):
        con = self.connect_mysql()
        try:
            cursor = con.cursor(buffered=True)
            cursor.execute(sql)
            con.commit()
        finally:
            con.close()
        return True


if __name__ == '__main__':
    _host, _user, _password = load_db_credentials()
    db_executor = DB(_host, _user, _password)
    if db_executor.setup_db():
        print("Set up database finished")
    else:
        print("Set up database failed")
