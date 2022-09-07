import cryptography.fernet
from typing import Union
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def generate_random_encryption_key():
    key = cryptography.fernet.Fernet.generate_key()
    return key


def build_crypter(keys):
    """
    Given a list of keys (or a key) builds the corresponding crypter
    """

    def parse_key(key):
        """
        If the key is a string we need to ensure that it can be decoded
        :param key:
        :return:
        """
        return cryptography.fernet.Fernet(key)

    if not keys:
        return None

    # Allow the use of key rotation;
    # if necessary turn the single key into a list of one
    if not isinstance(keys, (tuple, list)):
        keys = [keys, ]

    try:
        cryptographic_keys = [parse_key(k) for k in keys]
    except Exception as e:
        raise ImproperlyConfigured(f'Encryption keys incorrectly: {str(e)}')

    if len(cryptographic_keys) == 0:
        raise ImproperlyConfigured('No cryptographic_keys defined')

    return cryptography.fernet.MultiFernet(cryptographic_keys)


def build_default_crypter():
    """
    Builds a crypter for the configured keys (as specified in projects's settings)
    """
    configured_keys = getattr(settings, 'EJF_ENCRYPTION_KEYS', None)
    if callable(configured_keys):
        configured_keys = configured_keys()

    #if configured_keys is None:
    if not configured_keys:
        raise ImproperlyConfigured('EJF_ENCRYPTION_KEYS must be defined in settings')

    return build_crypter(configured_keys)


DEFAULT_CRYPTER = None


def get_default_crypter():
    """
    Retrieve (builds and caches) a crypter for the configured keys (as specified in projects's settings)
    """
    global DEFAULT_CRYPTER
    if DEFAULT_CRYPTER is None:
        DEFAULT_CRYPTER = build_default_crypter()
    return DEFAULT_CRYPTER


def encryption_disabled(force):
    if force:
        return False
    return getattr(settings, 'EJF_DISABLE_ENCRYPTION', False)


def is_encrypted(s: Union[str, bytes]) -> bool:
    """
    Check if the given string (or bytes) is the result of an encryption
    """
    result = True
    try:
        token = s.encode('utf-8') if (type(s) == str) else s
        timestamp, data = cryptography.fernet.Fernet._get_unverified_token_data(token)
    except cryptography.fernet.InvalidToken:
        result = False

    return result


def encrypt_str(s: str, crypter=None, force=False) -> bytes:
    """
    Encrypts the given string applying either the supplied crypter or, in None, the default crypter.
    If force=True, proceed even when encryption is disabled in project's settings.
    """

    assert type(s) in [str, ], 'wrong type %s' % str(type(s))

    #if keys is None and encryption_disabled():
    if encryption_disabled(force) \
       or is_encrypted(s):  # prevent double encryption
        return s.encode('utf-8')

    if crypter is None:
        crypter = get_default_crypter()

    # be sure to encode the string to bytes
    return crypter.encrypt(s.encode('utf-8'))


def decrypt_bytes(t: bytes, crypter=None, force=False) -> str:
    """
    Decrypts the given bytes and returns a string
    If force=True, proceed even when encryption is disabled in project's settings.
    """

    assert type(t) in [bytes, ]

    if encryption_disabled(force):
        return t.decode('utf-8')

    if crypter is None:
        crypter = get_default_crypter()

    try:
        value = crypter.decrypt(t).decode('utf-8')
    except Exception as e:
        # We were unable to decrypt the bytes; maybe that original key has been removed.
        # We return the undecrypted value for further inspection by the user
        try:
            value = str(t.decode('utf=8'))
        except:
            value = str(t)

    return value


def calc_encrypted_length(n, crypter=None):
    # calculates the characters necessary to hold an encrypted string of
    # n bytes
    return len(encrypt_str('a' * n, crypter))


def encrypt_values(data, crypter=None, force=False, json_skip_keys=None):
    # Inspired by:
    #   - Pedro Silva: "How to encrypt the values of a Postgres JSONField in Django"
    #     https://medium.com/@pedro.mvsilva/how-to-encrypt-the-values-of-a-postgres-jsonfield-in-django-abd2d9e802bf
    #   - LucasRoesler: "django-encrypted-json"
    #     https://github.com/LucasRoesler/django-encrypted-json

    if encryption_disabled(force):
        return data

    if json_skip_keys is None:
        json_skip_keys = []

    # Scan the lists, then encode each item recursively
    if isinstance(data, (list, tuple, set)):
        return [encrypt_values(v, crypter, force, json_skip_keys) for v in data]

    # Scan the dicts, then encode each item recursively
    if isinstance(data, dict):
        return {
            key: encrypt_values(value, crypter, force, json_skip_keys)
            for key, value in data.items()
        }

    # We finally have a simple item to work with, which can be:
    # a string, a number, a boolean, or null.
    # Since we don't want lo lose the item's type, we apply repr()
    # to obtain a printable representational string of it,
    # before proceding with the encryption
    encrypted_data = encrypt_str(repr(data), crypter, force)

    # Return the result as string, so that it can be JSON-serialized later on
    return encrypted_data.decode('utf-8')


def decrypt_values(data, crypter=None, force=False):

    if encryption_disabled(force):
        return data

    # Scan the lists, then decode each item recursively
    if isinstance(data, (list, tuple, set)):
        return [decrypt_values(x, crypter, force) for x in data]

    # Scan the dicts, then decode each item recursively
    if isinstance(data, dict):
        return {key: decrypt_values(value, crypter, force) for key, value in data.items()}

    # If we got so far, the data must be a string (the encrypted value)
    try:
        data = decrypt_bytes(data.encode('utf-8'), crypter, force)
        # for many Python types, when the result from repr() is passed to eval()
        # we will get the original object;
        # we take advantage of this to reconstruct both the original value and type
        value = eval(data)
    except cryptography.fernet.InvalidToken:
        value = str(data)
    except Exception as e:
        # ??? value = ''
        value = data
    return value

