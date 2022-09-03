from django.test import TestCase
from django.core.exceptions import ImproperlyConfigured

import cryptography.fernet

from encrypted_json_fields import fields


class EncryptionTestCase(TestCase):

    def setUp(self):
        # self.key1 = cryptography.fernet.Fernet.generate_key()
        # self.key2 = cryptography.fernet.Fernet.generate_key()
        pass

    def test_encryption(self):
        plain_text = "abc"
        encrypted_text = fields.encrypt_str(plain_text)
        decrypted_text = fields.decrypt_str(encrypted_text)
