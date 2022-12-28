import unittest
from unittest.mock import MagicMock

import main as main_module


class AppTestCase(unittest.TestCase):
    def setUp(self) -> None:
        main_module.auth.verify_password_callback = MagicMock(return_value=True)
        self.app = main_module.app
        self.app.config.update(dict(TESTING=True))
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        pass
