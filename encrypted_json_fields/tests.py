from django.test import TestCase
from django.core.exceptions import ImproperlyConfigured

import cryptography.fernet

from . import fields


class TestSettings(TestCase):
    def setUp(self):
        self.key1 = cryptography.fernet.Fernet.generate_key()
        self.key2 = cryptography.fernet.Fernet.generate_key()

    def test_settings(self):
        with self.settings(FIELD_ENCRYPTION_KEY=self.key1):
            fields.get_crypter()

    def test_settings_tuple(self):
        with self.settings(FIELD_ENCRYPTION_KEY=(self.key1, self.key2,)):
            fields.get_crypter()

    def test_settings_list(self):
        with self.settings(FIELD_ENCRYPTION_KEY=[self.key1, self.key2, ]):
            fields.get_crypter()

    def test_settings_empty(self):
        with self.settings(FIELD_ENCRYPTION_KEY=None):
            self.assertRaises(ImproperlyConfigured, fields.get_crypter)

        with self.settings(FIELD_ENCRYPTION_KEY=''):
            self.assertRaises(ImproperlyConfigured, fields.get_crypter)

        with self.settings(FIELD_ENCRYPTION_KEY=[]):
            self.assertRaises(ImproperlyConfigured, fields.get_crypter)

        with self.settings(FIELD_ENCRYPTION_KEY=tuple()):
            self.assertRaises(ImproperlyConfigured, fields.get_crypter)

    def test_settings_bad(self):
        with self.settings(FIELD_ENCRYPTION_KEY=self.key1[:5]):
            self.assertRaises(ImproperlyConfigured, fields.get_crypter)

        with self.settings(FIELD_ENCRYPTION_KEY=(self.key1[:5], self.key2,)):
            self.assertRaises(ImproperlyConfigured, fields.get_crypter)

        with self.settings(FIELD_ENCRYPTION_KEY=[self.key1[:5], self.key2[:5], ]):
            self.assertRaises(ImproperlyConfigured, fields.get_crypter)

    def test_retain_type_of_values(self):
        # EncryptedJSONField counts on having both value and type reconstructed
        # when applying eval() after repr(); this most the ensured at least for
        # the types managed by JSON
        values = [
            'a string',
            10,
            1.23,
            True,
            None,
            [1, 2, 'three', None],
        ]
        for value in values:
            value2 = eval(repr(value))
            self.assertEqual(value, value2)
            self.assertEqual(type(value), type(value2))
