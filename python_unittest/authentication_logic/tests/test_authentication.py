import unittest
from unittest.mock import MagicMock , patch

import python_unittest.authentication_logic.authentication.authentication
from python_unittest.authentication_logic.authentication.authentication import UserAuthentication, hash_password



class TestHashPassword(unittest.TestCase):
    def test_hash_password_creates_different_value(self):
        password = 'mypassword'
        hashed_password = hash_password(password)
        self.assertNotEqual(password, hashed_password)
        self.assertEqual(hashed_password, hash_password(password))


class TestUserRegister(unittest.TestCase):
    # @patch('builtins.input', return_value='testuser')
    # @patch('getpass.getpass', return_value='testpass')
    # @patch('sys.stdout', new_callable=io.StringIO)
    @patch(
        'python_unittest.authentication_logic.authentication.authentication.hash_password',
        return_value = 'hashed_pass'
    )
    def test_register(self,mock_hash):

        ua = UserAuthentication.__new__(UserAuthentication)
        ua.existance_username = MagicMock(return_value=False)
        ua.cur = MagicMock()
        ua.con = MagicMock()

        ua.register('testuser', 'testpass')

        mock_hash.assert_called_once_with('testpass')
        ua.cur.execute.assert_called_once_with(
            'INSERT INTO accounts(username, password) VALUES(?, ?)',
            ('testuser', 'hashed_pass')
        )

        ua.con.commit.assert_called_once()
        # self.assertIn('Register successfully!', mock_stdout.getvalue())
    @patch(
        'python_unittest.authentication_logic.authentication.authentication.hash_password',
        return_value = 'hashed_pass'
    )
    def test_register_existing_username(self,mock_hash):

        user_auth = UserAuthentication.__new__(UserAuthentication)
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

        user_auth.cur.execute.return_value.fetchone.return_value = ('hashed_pass',)

        with self.assertRaises(ValueError) as err:
            user_auth.validation_login('realuser', 'wrongpass')

        self.assertEqual(str(err.exception), 'incorrect password')

        user_auth.cur.execute.assert_called_once_with(
            "SELECT password FROM accounts WHERE username = ?",
            ('realuser',)
        )
    @patch(
        'python_unittest.authentication_logic.authentication.authentication.hash_password',
        return_value='hashed_pass'
    )
    def test_user_login_successfully(self,mock_hash):

        user_auth = UserAuthentication.__new__(UserAuthentication)
        user_auth.validation_login = MagicMock(return_value=True)
        user_auth.login('testuser', 'testpass')

        mock_hash.assert_called_once_with('testpass')
        user_auth.validation_login.assert_called_once_with('testuser', 'hashed_pass')


if __name__ == '__main__':
    unittest.main()
