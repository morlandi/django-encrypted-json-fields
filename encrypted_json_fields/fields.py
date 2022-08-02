import itertools
import json

import django.db
import django.db.models
from django.conf import settings
from django.core import validators
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
from django.utils.functional import cached_property
from django.core.serializers.json import DjangoJSONEncoder

import cryptography.fernet


def parse_key(key):
    """
    If the key is a string we need to ensure that it can be decoded
    :param key:
    :return:
    """
    return cryptography.fernet.Fernet(key)


def get_crypter():

    configured_keys = getattr(settings, 'FIELD_ENCRYPTION_KEY', None)
    if callable(configured_keys):
        configured_keys = configured_keys()

    if configured_keys is None:
        raise ImproperlyConfigured('FIELD_ENCRYPTION_KEY must be defined in settings')

    try:
        # Allow the use of key rotation
        if isinstance(configured_keys, (tuple, list)):
            keys = [parse_key(k) for k in configured_keys]
        else:
            # else turn the single key into a list of one
            keys = [parse_key(configured_keys), ]
    except Exception as e:
        raise ImproperlyConfigured(f'FIELD_ENCRYPTION_KEY defined incorrectly: {str(e)}')

    if len(keys) == 0:
        raise ImproperlyConfigured('No keys defined in setting FIELD_ENCRYPTION_KEY')

    return cryptography.fernet.MultiFernet(keys)


#CRYPTER = get_crypter()
CRYPTER = None


def get_crypted_lazy():
    global CRYPTER
    if CRYPTER is None:
        CRYPTER = get_crypter()
    return CRYPTER


def encrypt_str(s):
    # be sure to encode the string to bytes
    return get_crypted_lazy().encrypt(s.encode('utf-8'))


def decrypt_str(t):
    # be sure to decode the bytes to a string
    return get_crypted_lazy().decrypt(t.encode('utf-8')).decode('utf-8')


def calc_encrypted_length(n):
    # calculates the characters necessary to hold an encrypted string of
    # n bytes
    return len(encrypt_str('a' * n))


class EncryptedMixin(object):
    def to_python(self, value):
        if value is None:
            return value

        if isinstance(value, (bytes, str)):
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            try:
                value = decrypt_str(value)
            except cryptography.fernet.InvalidToken:
                pass

        return super(EncryptedMixin, self).to_python(value)

    def from_db_value(self, value, *args, **kwargs):
        return self.to_python(value)

    def get_db_prep_save(self, value, connection):
        value = super(EncryptedMixin, self).get_db_prep_save(value, connection)

        if value is None:
            return value
        # decode the encrypted value to a unicode string, else this breaks in pgsql
        return (encrypt_str(str(value))).decode('utf-8')

    def get_internal_type(self):
        return "TextField"

    def deconstruct(self):
        name, path, args, kwargs = super(EncryptedMixin, self).deconstruct()

        if 'max_length' in kwargs:
            del kwargs['max_length']

        return name, path, args, kwargs


class EncryptedCharField(EncryptedMixin, django.db.models.CharField):
    pass


class EncryptedTextField(EncryptedMixin, django.db.models.TextField):
    pass


class EncryptedDateField(EncryptedMixin, django.db.models.DateField):
    pass


class EncryptedDateTimeField(EncryptedMixin, django.db.models.DateTimeField):
    # credit to Oleg Pesok...
    def to_python(self, value):
        value = super(EncryptedDateTimeField, self).to_python(value)

        if value is not None and settings.USE_TZ and timezone.is_naive(value):
            default_timezone = timezone.get_default_timezone()
            value = timezone.make_aware(value, default_timezone)

        return value


class EncryptedEmailField(EncryptedMixin, django.db.models.EmailField):
    pass


class EncryptedBooleanField(EncryptedMixin, django.db.models.BooleanField):

    def get_db_prep_save(self, value, connection):
        if value is None:
            return value
        if value is True:
            value = '1'
        elif value is False:
            value = '0'
        # decode the encrypted value to a unicode string, else this breaks in pgsql
        return encrypt_str(str(value)).decode('utf-8')


class EncryptedNumberMixin(EncryptedMixin):
    max_length = 20

    @cached_property
    def validators(self):
        # These validators can't be added at field initialization time since
        # they're based on values retrieved from `connection`.
        range_validators = []
        internal_type = self.__class__.__name__[9:]
        min_value, max_value = django.db.connection.ops.integer_field_range(internal_type)
        if min_value is not None:
            range_validators.append(validators.MinValueValidator(min_value))
        if max_value is not None:
            range_validators.append(validators.MaxValueValidator(max_value))
        return list(itertools.chain(self.default_validators, self._validators, range_validators))


class EncryptedIntegerField(EncryptedNumberMixin, django.db.models.IntegerField):
    description = "An IntegerField that is encrypted before " \
                  "inserting into a database using the python cryptography " \
                  "library"
    pass


class EncryptedPositiveIntegerField(EncryptedNumberMixin, django.db.models.PositiveIntegerField):
    pass


class EncryptedSmallIntegerField(EncryptedNumberMixin, django.db.models.SmallIntegerField):
    pass


class EncryptedPositiveSmallIntegerField(
        EncryptedNumberMixin, django.db.models.PositiveSmallIntegerField
):
    pass


class EncryptedBigIntegerField(EncryptedNumberMixin, django.db.models.BigIntegerField):
    pass

#################################################################################
# Encryption for JSONField

class EncryptedJSONField(django.db.models.JSONField):

    def __init__(self, *args, **kwargs):
        self.skip_keys = kwargs.pop("skip_keys", [])
        super().__init__(*args, **kwargs)

    def get_db_prep_save(self, value, connection):
        """
        Return field's value prepared for saving into a database.

        Here, we encrypt all the values in the object, while keeping intact
        the keys of any dictionary inside the object, if any.
        More precisely, well'encrypt the repr() of the values to preserve the type;
        see encrypt_values().
        """
        value = encrypt_values(value)
        # The encrypted result is itself a valid JSON-serializable object,
        # so we pass it to our base class for proper serialization
        return super().get_db_prep_save(value, connection)

    def from_db_value(self, value, expression, connection):
        """
        Adapted from django.db.models.JSONField to descrypt the values
        """
        from django.db.models.fields.json import KeyTransform

        if value is None:
            return value
        # Some backends (SQLite at least) extract non-string values in their
        # SQL datatypes.
        if isinstance(expression, KeyTransform) and not isinstance(value, str):
            return value
        try:
            #return json.loads(value, cls=self.decoder)
            # Deserialize the JSON,
            # then decrypt the values of the resulting object
            obj = json.loads(value, cls=self.decoder)
            return decrypt_values(obj)
        except json.JSONDecodeError:
            return value


def encrypt_values(data, skip_keys=None):
    # Inspired by:
    #   - Pedro Silva: "How to encrypt the values of a Postgres JSONField in Django"
    #     https://medium.com/@pedro.mvsilva/how-to-encrypt-the-values-of-a-postgres-jsonfield-in-django-abd2d9e802bf
    #   - LucasRoesler: "django-encrypted-json"
    #     https://github.com/LucasRoesler/django-encrypted-json
    if skip_keys is None:
        skip_keys = []

    # Scan the lists, then encode each item recursively
    if isinstance(data, (list, tuple, set)):
        return [encrypt_values(x, skip_keys) for x in data]

    # Scan the dicts, then encode each item recursively
    if isinstance(data, dict):
        return {
            key: encrypt_values(value, skip_keys)
            for key, value in data.items()
        }

    # We finally have a simple item to work with, which can be:
    # a string, a number, a boolean, or null.
    # Since we don't want lo lose the item's type, we apply repr()
    # to obtain a printable representational string of it,
    # before proceding with the encryption
    encrypted_data = encrypt_str(repr(data))

    # Return the result as string, so that it can be JSON-serialized later on
    return encrypted_data.decode()


def decrypt_values(data):

    # Scan the lists, then decode each item recursively
    if isinstance(data, (list, tuple, set)):
        return [decrypt_values(x) for x in data]

    # Scan the dicts, then decode each item recursively
    if isinstance(data, dict):
        return {key: decrypt_values(value) for key, value in data.items()}

    # If we got so far, the data must be a string (the encrypted value)
    try:
        data = decrypt_str(data)
        # for many Python types, when the result from repr() is passed to eval()
        # we will get the original object;
        # we take advantage of this to reconstruct both the original value and type
        value = eval(data)
    except cryptography.fernet.InvalidToken:
        value = str(data)
    return value

