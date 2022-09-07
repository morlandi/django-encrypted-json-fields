from django.test import TestCase
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


import cryptography.fernet

from encrypted_json_fields import helpers
from encrypted_json_fields.helpers import build_crypter


class CrypterTestCase(TestCase):

    def setUp(self):
        # self.key1 = cryptography.fernet.Fernet.generate_key()
        # self.key2 = cryptography.fernet.Fernet.generate_key()
        pass

    def test_encryption(self):
        """
        python manage.py test encrypted_json_fields.tests.test_helpers.CrypterTestCase.test_encryption
        """
        plain_text = "the quick brown fox jumps over the lazy dog"

        # Encrypt/decrypt using the configured keys
        encrypted_bytes_1 = helpers.encrypt_str(plain_text)
        decrypted_text_1 = helpers.decrypt_bytes(encrypted_bytes_1)

        self.assertFalse(helpers.is_encrypted(plain_text))
        self.assertTrue(helpers.is_encrypted(encrypted_bytes_1))
        self.assertFalse(helpers.is_encrypted(decrypted_text_1))
        self.assertEqual(plain_text, decrypted_text_1)

        # Encrypt/decrypt supplying a specific key
        keys = [helpers.generate_random_encryption_key(), ]
        crypter = build_crypter(keys)
        encrypted_bytes_2 = helpers.encrypt_str(plain_text, crypter)
        decrypted_text_2 = helpers.decrypt_bytes(encrypted_bytes_2, crypter)

        self.assertFalse(helpers.is_encrypted(plain_text))
        self.assertTrue(helpers.is_encrypted(encrypted_bytes_2))
        self.assertFalse(helpers.is_encrypted(decrypted_text_2))
        self.assertEqual(plain_text, decrypted_text_2)

        # If we try to decrypt the previous result, we fail
        decrypted_text_3 = helpers.decrypt_bytes(encrypted_bytes_1, crypter)
        self.assertNotEqual(plain_text, decrypted_text_3)
        self.assertTrue(helpers.is_encrypted(decrypted_text_3))

        # Unless we use both keys
        keys.append(settings.EJF_ENCRYPTION_KEYS)
        crypter = build_crypter(keys)
        decrypted_text_4 = helpers.decrypt_bytes(encrypted_bytes_1, crypter)
        self.assertEqual(plain_text, decrypted_text_4)
        self.assertFalse(helpers.is_encrypted(decrypted_text_4))

    def test_is_encrypted(self):

        plain_text = "the quick brown fox jumps over the lazy dog"

        encrypted_bytes = helpers.encrypt_str(plain_text)
        self.assertTrue(helpers.is_encrypted(encrypted_bytes))
        encrypted_text = encrypted_bytes.decode('utf-8')
        self.assertTrue(helpers.is_encrypted(encrypted_text))

        self.assertFalse(helpers.is_encrypted('bad string'))

    def test_encryption_disabled(self):

        plain_text = "the quick brown fox jumps over the lazy dog"
        encrypted_bytes = helpers.encrypt_str(plain_text)
        encrypted_str =  encrypted_bytes.decode('utf-8')

        self.assertFalse(helpers.is_encrypted(plain_text))
        self.assertTrue(helpers.is_encrypted(encrypted_bytes))
        self.assertNotEqual(plain_text, encrypted_str)
        self.assertEqual(plain_text, helpers.decrypt_bytes(encrypted_bytes))

        with self.settings(EJF_DISABLE_ENCRYPTION=True):

            encrypted_bytes = helpers.encrypt_str(plain_text)
            encrypted_str =  encrypted_bytes.decode('utf-8')
            self.assertFalse(helpers.is_encrypted(plain_text))
            self.assertFalse(helpers.is_encrypted(helpers.encrypt_str(plain_text)))
            self.assertEqual(plain_text, encrypted_str)
            self.assertEqual(plain_text, helpers.decrypt_bytes(encrypted_bytes))

    def test_prevent_double_encryption(self):

        plain_text = "the quick brown fox jumps over the lazy dog"
        encrypted_bytes = helpers.encrypt_str(plain_text)
        encrypted_str =  encrypted_bytes.decode('utf-8')

        self.assertFalse(helpers.is_encrypted(plain_text))
        self.assertTrue(helpers.is_encrypted(encrypted_bytes))
        self.assertTrue(helpers.is_encrypted(encrypted_str))

        encrypted_bytes2 = helpers.encrypt_str(encrypted_str)
        encrypted_str2 =  encrypted_bytes.decode('utf-8')
        self.assertTrue(helpers.is_encrypted(encrypted_bytes2))
        self.assertTrue(helpers.is_encrypted(encrypted_str2))

        plain_text2 = helpers.decrypt_bytes(encrypted_bytes2)
        self.assertEqual(plain_text, plain_text2)

    def test_prevent_double_decryption(self):

        plain_text = "the quick brown fox jumps over the lazy dog"
        encrypted_bytes = helpers.encrypt_str(plain_text)

        text2 = helpers.decrypt_bytes(encrypted_bytes)
        text3 = helpers.decrypt_bytes(plain_text.encode('utf-8'))
        self.assertEqual(plain_text, text2)
        self.assertEqual(plain_text, text3)
