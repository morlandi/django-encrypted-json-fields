from django.test import TestCase
from django.core.exceptions import ImproperlyConfigured

import cryptography.fernet

from encrypted_json_fields import helpers
from encrypted_json_fields import fields


class TestSettings(TestCase):

    def setUp(self):
        self.key1 = cryptography.fernet.Fernet.generate_key()
        self.key2 = cryptography.fernet.Fernet.generate_key()

    def test_settings(self):
        with self.settings(EJF_ENCRYPTION_KEYS=self.key1):
            helpers.build_default_crypter()

    def test_settings_tuple(self):
        with self.settings(EJF_ENCRYPTION_KEYS=(self.key1, self.key2,)):
            helpers.build_default_crypter()

    def test_settings_list(self):
        with self.settings(EJF_ENCRYPTION_KEYS=[self.key1, self.key2, ]):
            helpers.build_default_crypter()

    def test_settings_empty(self):
        with self.settings(EJF_ENCRYPTION_KEYS=None):
            self.assertRaises(ImproperlyConfigured, helpers.build_default_crypter)

        with self.settings(EJF_ENCRYPTION_KEYS=''):
            self.assertRaises(ImproperlyConfigured, helpers.build_default_crypter)

        with self.settings(EJF_ENCRYPTION_KEYS=[]):
            self.assertRaises(ImproperlyConfigured, helpers.build_default_crypter)

        with self.settings(EJF_ENCRYPTION_KEYS=tuple()):
            self.assertRaises(ImproperlyConfigured, helpers.build_default_crypter)

    def test_settings_bad(self):
        with self.settings(EJF_ENCRYPTION_KEYS=self.key1[:5]):
            self.assertRaises(ImproperlyConfigured, helpers.build_default_crypter)

        with self.settings(EJF_ENCRYPTION_KEYS=(self.key1[:5], self.key2,)):
            self.assertRaises(ImproperlyConfigured, helpers.build_default_crypter)

        with self.settings(EJF_ENCRYPTION_KEYS=[self.key1[:5], self.key2[:5], ]):
            self.assertRaises(ImproperlyConfigured, helpers.build_default_crypter)

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
