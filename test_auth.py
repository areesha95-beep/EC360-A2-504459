import unittest
from auth_service import register_user, hash_password, verify_password


class TestAuth(unittest.TestCase):
    def test_successful_registration(self):
        users = {}
        r = register_user(users, "alice@example.com", "StrongPass1234")
        self.assertEqual(r["status"], 201)

    def test_duplicate_registration(self):
        users = {}
        register_user(users, "alice@example.com", "StrongPass1234")
        r = register_user(users, "alice@example.com", "StrongPass1234")
        self.assertEqual(r["status"], 409)

    def test_password_hash_verifies(self):
        h = hash_password("StrongPass1234")
        self.assertTrue(verify_password("StrongPass1234", h))
        self.assertFalse(verify_password("wrong", h))


if __name__ == "__main__":
    unittest.main()