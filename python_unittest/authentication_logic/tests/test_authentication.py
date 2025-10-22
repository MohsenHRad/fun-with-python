import unittest
from unittest.mock import MagicMock,patch
from python_unittest.authentication_logic.authentication.authentication import UserAuthentication , hash_password

class TestHashPassword(unittest.TestCase):
    def test_hash_password_creates_different_value(self):
        password = 'mypassword'
        hashed_password = hash_password(password)
        self.assertNotEqual(password,hashed_password)
        self.assertEqual(hashed_password,hash_password(password))



if __name__ == '__main__':
    unittest.main()