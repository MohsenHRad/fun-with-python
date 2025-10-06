import io

from python_unittest.authentication_logic.authentication.authentication import UserAuthentication

import unittest
from unittest.mock import patch, MagicMock


# PassHash test
class TestPassHash(unittest.TestCase):

    def setUp(self):
        UA = UserAuthentication()
        self.password = input("Enter a password to hash: ")
        self.wrong_password = input("Enter a wrong password to test: ")
        self.passhash = UA.hash_password(self.password)

    def test_hash_password(self):
        hashed = self.passhash
        self.assertNotEqual(self.password, hashed)
        self.assertTrue(UA.verify_password(self.password, hashed))

    def test_verify_password(self):
        hashed = self.passhash
        self.assertTrue(UA.verify_password(self.password, hashed))
        self.assertFalse(UA.verify_password(self.wrong_password, hashed))
        self.assertFalse(UA.verify_password("", hashed))
        self.assertFalse(UA.verify_password(None, hashed))


class TestUserRegister(unittest.TestCase):
    @patch('builtins.input', return_value='testuser')
    @patch('getpass.getpass', return_value='testpass')
    @patch('sys.stdout', new_callable=io.StringIO)
    def test_register(self, mock_stdout, mock_getpass, mock_input):
        ua = UserAuthentication.__new__(UserAuthentication)

        ua.hash_password = MagicMock()
        ua.existance_username = MagicMock(return_value=False)
        ua.existance_password = MagicMock(return_value=False)

        ua.cur = MagicMock()
        ua.con = MagicMock()

        ua.register()

        ua.hash_password.assert_called_once_with('testpass')
        ua.cur.execute.assert_called_once_with(
            'INSERT INTO accounts(username, password) VALUES(?, ?)',
            ('testuser', 'testpass')
        )

        ua.con.commit.assert_called_once()
        self.assertIn('Register successfully!', mock_stdout.getvalue())


if __name__ == '__main__':
    unittest.main()
