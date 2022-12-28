import json
import unittest
from unittest.mock import patch, MagicMock

from app_test_case import AppTestCase
from db import DB

DUMMY_USER_INFO = {
    "id": "123456",
    "first_name": "TTTTTtest",
    "last_name": "e99999",
    "password": "somesw222ord",
    "username": "jeuuddffd@example.com",
    "account_created": "2022-10-12 22:34:39",
    "account_updated": "2022-10-12 22:34:39",
    "verified": "TRUE"
}


@patch('db.load_db_credentials', return_value=('ttt','ubuntu', 'test1234'))
class TestMain(AppTestCase):
    # @patch.object(main_time, 'time', return_value='123')
    # def test_ping(self, *_: MagicMock):
    #     with self.client as client:
    #         response = client.get('/ping')
    #         self.assertEqual(response.status_code, 200)
    #         self.assertEqual(response.get_data(as_text=True), 'pong at 123')

    # def test_login(self):
    #     with self.client as client:
    #         response = client.post('/authenticate', json={"username": "AAA"})
    #         self.assertEqual(response.status_code, 200)
    #         self.assertEqual(response.get_json()['username'], 'AAA')

    def test_1(self, *_: MagicMock):
        resp = self.client.get("/healthz")

        self.assertEqual(200, resp.status_code)

    def test_2(self, *_: MagicMock):
        resp = self.client.post("/v1/account", data="{}")

        self.assertEqual(400, resp.status_code)

    # @patch.object(
    #     DB, 'execute_and_get_result', return_value=[DUMMY_USER_INFO]
    # )
    # def test_3(self, *_: MagicMock):
    #     resp = self.client.get("/v1/account/f0b6600219ff6416fe01cefb90735c94", data=json.dumps({}))
    #
    #     self.assertEqual(200, resp.status_code)
    #
    # @patch.object(DB, 'execute', return_value=True)
    # @patch.object(DB, 'execute_and_get_result', return_value=[DUMMY_USER_INFO])
    # def test_4(self, mock_execute_and_get_result: MagicMock, mock_db_execute: MagicMock, mock_load_credentials: MagicMock):
    #     resp = self.client.put("/v1/account/f0b6600219ff6416fe01cefb90735c94", data=json.dumps({'username': 'yyds'}))
    #
    #     self.assertEqual(204, resp.status_code)
    #     mock_db_execute.assert_called_once_with(
    #         'update webapp set username="yyds" where id="f0b6600219ff6416fe01cefb90735c94"'
    #     )


if __name__ == "__main__":
    unittest.main()
