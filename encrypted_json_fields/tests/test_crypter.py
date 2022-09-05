from django.test import TestCase
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


import cryptography.fernet

from encrypted_json_fields import crypter


class CrypterTestCase(TestCase):

    def setUp(self):
        # self.key1 = cryptography.fernet.Fernet.generate_key()
        # self.key2 = cryptography.fernet.Fernet.generate_key()
        pass

    def test_encryption(self):
        """
        python manage.py test encrypted_json_fields.tests.test_crypter.CrypterTestCase.test_encryption
        """
        plain_text = "the quick brown fox jumps over the lazy dog"

        # Encrypt/decrypt using the configured keys
        encrypted_bytes_1 = crypter.encrypt_str(plain_text)
        decrypted_text_1 = crypter.decrypt_bytes(encrypted_bytes_1)

        self.assertFalse(crypter.is_encrypted(plain_text))
        self.assertTrue(crypter.is_encrypted(encrypted_bytes_1))
        self.assertFalse(crypter.is_encrypted(decrypted_text_1))
        self.assertEqual(plain_text, decrypted_text_1)

        # Encrypt/decrypt supplying a specific key
        keys = [crypter.generate_random_encryption_key(), ]
        encrypted_bytes_2 = crypter.encrypt_str(plain_text, keys)
        decrypted_text_2 = crypter.decrypt_bytes(encrypted_bytes_2, keys)

        self.assertFalse(crypter.is_encrypted(plain_text))
        self.assertTrue(crypter.is_encrypted(encrypted_bytes_2))
        self.assertFalse(crypter.is_encrypted(decrypted_text_2))
        self.assertEqual(plain_text, decrypted_text_2)

        # If we try to decrypt the previous result, we fail
        decrypted_text_3 = crypter.decrypt_bytes(encrypted_bytes_1, keys)
        self.assertNotEqual(plain_text, decrypted_text_3)
        self.assertTrue(crypter.is_encrypted(decrypted_text_3))

        # Unless we use both keys
        keys.append(settings.EJF_ENCRYPTION_KEYS)
        decrypted_text_4 = crypter.decrypt_bytes(encrypted_bytes_1, keys)
        self.assertEqual(plain_text, decrypted_text_4)
        self.assertFalse(crypter.is_encrypted(decrypted_text_4))

    def test_is_encrypted(self):

        plain_text = "the quick brown fox jumps over the lazy dog"

        encrypted_bytes = crypter.encrypt_str(plain_text)
        self.assertTrue(crypter.is_encrypted(encrypted_bytes))
        encrypted_text = encrypted_bytes.decode('utf-8')
        self.assertTrue(crypter.is_encrypted(encrypted_text))

        self.assertFalse(crypter.is_encrypted('bad string'))

    def test_encryption_disabled(self):

        plain_text = "the quick brown fox jumps over the lazy dog"
        encrypted_bytes = crypter.encrypt_str(plain_text)
        encrypted_str =  encrypted_bytes.decode('utf-8')

        self.assertFalse(crypter.is_encrypted(plain_text))
        self.assertTrue(crypter.is_encrypted(encrypted_bytes))
        self.assertNotEqual(plain_text, encrypted_str)
        self.assertEqual(plain_text, crypter.decrypt_bytes(encrypted_bytes))

        with self.settings(EJF_DISABLE_ENCRYPTION=True):

            encrypted_bytes = crypter.encrypt_str(plain_text)
            encrypted_str =  encrypted_bytes.decode('utf-8')
            self.assertFalse(crypter.is_encrypted(plain_text))
            self.assertFalse(crypter.is_encrypted(crypter.encrypt_str(plain_text)))
            self.assertEqual(plain_text, encrypted_str)
            self.assertEqual(plain_text, crypter.decrypt_bytes(encrypted_bytes))
