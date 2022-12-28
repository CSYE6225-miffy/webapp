import db
import s3


class Executor:
    def __init__(self) -> None:
        self._db_executor = None
        self._s3_executor = None

    @property
    def db(self) -> db.DB:
        if self._db_executor is None:
            host, user, password = db.load_db_credentials()
            self._db_executor = db.DB(host, user, password)
        return self._db_executor

    @property
    def s3(self) -> s3.S3:
        if self._s3_executor is None:
            self._s3_executor = s3.S3()
        return self._s3_executor


executor = Executor()
