import textwrap
import typing as t
from unittest.mock import patch, MagicMock, Mock

from app_test_case import AppTestCase
from db import DB


class DummyConnection:
    def __init__(
            self,
            column_names: t.Optional[t.List[str]] = None,
            query_results: t.Optional[t.List[t.Tuple[t.Any, ...]]] = None,
    ):
        self.column_names: t.List[str] = column_names or []
        self.query_results: t.List[t.Tuple[t.Any, ...]] = query_results or []

    def cursor(self, *args, **kwargs):
        mocked_object = Mock()
        mocked_object.column_names = self.column_names
        mocked_object.fetchall.return_value = self.query_results
        return mocked_object

    def close(self):
        pass


class TestDBExecutor(AppTestCase):
    @patch.object(DB, 'connect_mysql', return_value=DummyConnection())
    def test_connect_mysql(self, *_: MagicMock):
        db_executor = DB(host='ttt', user='ubuntu', password='test1234')
        con = db_executor.connect_mysql()
        self.assertTrue(isinstance(con, DummyConnection))

    @patch.object(
        DB, 'connect_mysql', return_value=DummyConnection(
            column_names=['user_id', 'user_name'], query_results=[('123', 'Lily')],
        )
    )
    def test_execute_and_get_result(self, *_: MagicMock):
        db_executor = DB(host='ttt', user='ubuntu', password='test1234')
        sql = textwrap.dedent(
            '''\
            SELECT * FROM dummy_table;
            '''
        )
        result = db_executor.execute_and_get_result(sql)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['user_id'], '123')
        self.assertEqual(result[0]['user_name'], 'Lily')
