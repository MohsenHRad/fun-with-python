import unittest
from unittest.mock import MagicMock

from python_unittest.authentication_logic.authentication.authentication import UserAuthentication


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
    # @patch('builtins.input', return_value='testuser')
    # @patch('getpass.getpass', return_value='testpass')
    # @patch('sys.stdout', new_callable=io.StringIO)
    def test_register(self):
        ua = UserAuthentication.__new__(UserAuthentication)

        ua.hash_password = MagicMock(return_value='hashedpass')
        ua.existance_username = MagicMock(return_value=False)
        ua.cur = MagicMock()
        ua.con = MagicMock()

        ua.register('testuser', 'testpass')

        ua.hash_password.assert_called_once_with('testpass')
        ua.cur.execute.assert_called_once_with(
            'INSERT INTO accounts(username, password) VALUES(?, ?)',
            ('testuser', 'hashedpass')
        )

        ua.con.commit.assert_called_once()
        # self.assertIn('Register successfully!', mock_stdout.getvalue())

    def test_register_existing_username(self):
        user_auth = UserAuthentication.__new__(UserAuthentication)

        user_auth.hash_password = MagicMock(return_value='hashedpass')
        user_auth.existance_username = MagicMock(return_value=True)
        user_auth.cur = MagicMock()
        user_auth.con = MagicMock()

        with self.assertRaises(ValueError) as errormsg:
            user_auth.register('existinguser', 'testpass')

        self.assertEqual(str(errormsg.exception), 'username already exists')

        user_auth.cur.execute.assert_not_called()
        user_auth.con.commit.assert_not_called()


class TestUserLogin(unittest.TestCase):

    def test_validation_login_user_not_found(self):
        user_auth = UserAuthentication.__new__(UserAuthentication)

        user_auth.cur = MagicMock()

        user_auth.cur.execute.return_value.fetchone.return_value = None

        with self.assertRaises(ValueError) as err:
            user_auth.validation_login('fakeuser', 'testpass')

        self.assertEqual(str(err.exception), 'username not found')

        user_auth.cur.execute.assert_called_once_with(
            "SELECT password FROM accounts WHERE username = ?",
            ('fakeuser',))

    def test_validation_login_incorrect_password(self):
        user_auth = UserAuthentication.__new__(UserAuthentication)
        user_auth.cur = MagicMock()

        user_auth.cur.execute.return_value.fetchone.return_value = ('hashedpass',)

        with self.assertRaises(ValueError) as err:
            user_auth.validation_login('realuser', 'wrongpass')

        self.assertEqual(str(err.exception), 'incorrect password')

        user_auth.cur.execute.assert_called_once_with(
            "SELECT password FROM accounts WHERE username = ?",
            ('realuser',)
        )

    def test_user_login_successfully(self):
        user_auth = UserAuthentication.__new__(UserAuthentication)
        user_auth.hash_password = MagicMock(return_value='hashedpass')
        user_auth.validation_login = MagicMock(return_value=True)

        user_auth.login('testuser', 'testpass')

        user_auth.hash_password.assert_called_once_with('testpass')
        user_auth.validation_login.assert_called_once_with('testuser', 'hashedpass')


if __name__ == '__main__':
    unittest.main()
