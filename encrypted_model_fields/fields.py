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


CRYPTER = get_crypter()


def encrypt_str(s):
    # be sure to encode the string to bytes
    return CRYPTER.encrypt(s.encode('utf-8'))


def decrypt_str(t):
    # be sure to decode the bytes to a string
    return CRYPTER.decrypt(t.encode('utf-8')).decode('utf-8')


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


def trace_method(fn):
    """
    Sample usage:

        class MyClass(object):
            ...

            @trace_method
            def myfunc(self, user, obj):
                ...
    """
    def trace1(message):
        print('\x1b[1;37;44m %s \x1b[1;39;49m' % str(message))

    def trace2(message):
        print('\x1b[1;33;40m %s \x1b[1;39;49m' % str(message))

    def trace3(message):
        print('\x1b[0;36;40m %s \x1b[1;39;49m' % str(message))

    def func_wrapper(*args, **kwargs):

        trace1('>>> %s()' % fn.__name__)

        # remove "self"
        targs = args[1:]
        if (targs):
            for arg in targs:
                trace2(arg)

        if kwargs:
            for key, value in kwargs.items():
                trace2('"%s": %s' % (key, value))

        ret = fn(*args, **kwargs)
        trace3(ret)
        trace1('<<< %s()' % fn.__name__)
        return ret
    return func_wrapper


# https://medium.com/@pedro.mvsilva/how-to-encrypt-the-values-of-a-postgres-jsonfield-in-django-abd2d9e802bf


def encrypt_values(data, skip_keys=None):
    # cypher = AES.new(
    #     FIELD_ENCRYPTION_KEY, AES.MODE_CBC, FIELD_ENCRYPTION_IV
    # )

    if skip_keys is None:
        skip_keys = []

    if isinstance(data, (list, tuple, set)):
        return [encrypt_values(x, skip_keys) for x in data]

    if isinstance(data, dict):
        return {
            key: encrypt_values(value, skip_keys).decode()
            for key, value in data.items()
        }

    return encrypt_str(repr(data))




    # if isinstance(data, int) or isinstance(data, float):
    #     #data = str(data).encode()
    #     return encrypt_str(str(data))
    #     #return b64encode(cypher.encrypt(pad(data, AES.block_size))).decode()

    # if data is None:
    #     #data = "".encode()
    #     return encrypt_str("")
    #     #return b64encode(cypher.encrypt(pad(data, AES.block_size))).decode()

    # if isinstance(data, str):
    #     #data = data.encode()

    #     return encrypt_str(data)
    #     #return b64encode(cypher.encrypt(pad(data, AES.block_size))).decode()

    return json.dumps(data, cls=DjangoJSONEncoder)


def decrypt_values(data):
    # d_cypher = AES.new(
    #     settings.FIELD_ENCRYPTION_KEY, AES.MODE_CBC, settings.FIELD_ENCRYPTION_IV
    # )

    if isinstance(data, (list, tuple, set)):
        return [decrypt_values(x) for x in data]

    if isinstance(data, dict):
        return {key: decrypt_values(value) for key, value in data.items()}

    if isinstance(data, str):
        #data = b64decode(data)
        data = decrypt_str(data)

    return data

    # try:
    #     #value = unpad(d_cypher.decrypt(data), AES.block_size)
    #     value = decrypt_str(data)
    # except ValueError:
    #     value = data

    # value = value.decode()
    # try:
    #     return json.loads(value)
    # except Exception:
    #     value = check_for_bool(value)
    #     return value


class EncryptedJSONField(django.db.models.JSONField):

    def __init__(self, *args, **kwargs):
        self.skip_keys = kwargs.pop("skip_keys", [])
        super().__init__(*args, **kwargs)

    # # def from_db_value(self, value, expression, context):
    # #     value = decrypt_values(value)
    # #     return value

    # # def get_prep_value(self, value):
    # #     if self.blank and value == "":
    # #         if self.default != NOT_PROVIDED:
    # #             if callable(self.default):
    # #                 value = self.default()
    # #             else:
    # #                 value = self.default
    # #         else:
    # #             value = {}

    # #     if self.null and value is None:
    # #         return None

    # #     value = encrypt_values(value)
    # #     import ipdb; ipdb.set_trace()


    # # def to_python(self, value):
    # #     if value is None:
    # #         return value

    # #     # if isinstance(value, (bytes, str)):
    # #     #     if isinstance(value, bytes):
    # #     #         value = value.decode('utf-8')
    # #     #     try:
    # #     #         value = decrypt_str(value)
    # #     #     except cryptography.fernet.InvalidToken:
    # #     #         pass

    # #     return super().to_python(value)


    # def to_python(self, value):
    #     if value is None:
    #         return value

    #     #value = decrypt_values(value)
    #     # if isinstance(value, (bytes, str)):
    #     #     if isinstance(value, bytes):
    #     #         value = value.decode('utf-8')
    #     #     try:
    #     #         value = decrypt_values(value)
    #     #     except cryptography.fernet.InvalidToken:
    #     #         pass

    #     import ipdb; ipdb.set_trace()
    #     value = json.loads(value)
    #     return super().to_python(value)

    # def from_db_value(self, value, *args, **kwargs):
    #     value = super().from_db_value(value, *args, **kwargs)
    #     return self.to_python(value)

    # # def get_prep_value(self, value):
    # #     import ipdb; ipdb.set_trace()
    # #     if value is None:
    # #         return value
    # #     return json.dumps(value, cls=self.encoder)

    # def get_db_prep_save(self, value, connection):
    #     #value = encrypt_values(value)
    #     value = super().get_db_prep_save(value, connection)
    #     if value is None:
    #         return value
    #     return json.dumps(value, cls=DjangoJSONEncoder)



    #     # value = self.get_prep_value(value)

    #     # if value is None:
    #     #     return value
    #     # # decode the encrypted value to a unicode string, else this breaks in pgsql
    #     # #return (encrypt_str(str(value))).decode('utf-8')

    #     # import ipdb; ipdb.set_trace()

    #     #return value

    @trace_method
    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        # Some backends (SQLite at least) extract non-string values in their
        # SQL datatypes.
        from django.db.models.fields.json import KeyTransform

        if isinstance(expression, KeyTransform) and not isinstance(value, str):
            return value
        try:
            return json.loads(value, cls=self.decoder)
        except json.JSONDecodeError:
            return value

    @trace_method
    def get_prep_value(self, value):
        if value is None:
            return value
        return json.dumps(value, cls=self.encoder)

    # def get_transform(self, name):
    #     import ipdb; ipdb.set_trace()
    #     transform = super().get_transform(name)
    #     if transform:
    #         return transform
    #     return KeyTransformFactory(name)

    @trace_method
    def validate(self, value, model_instance):
        super().validate(value, model_instance)
        try:
            json.dumps(value, cls=self.encoder)
        except TypeError:
            raise exceptions.ValidationError(
                self.error_messages['invalid'],
                code='invalid',
                params={'value': value},
            )

    # def value_to_string(self, obj):
    #     import ipdb; ipdb.set_trace()
    #     return self.value_from_object(obj)








# >>> pickle.dumps(1)
# b'\x80\x04K\x01.'
# >>> pickle.loads(pickle.dumps(1))
# 1
# >>> pickle.loads(pickle.dumps(1.3))
# 1.3
# >>> type(pickle.loads(pickle.dumps(1.3)))
# <class 'float'>
# >>> type(pickle.loads(pickle.dumps(1)))
# <class 'int'>
# >>> type(pickle.loads(pickle.dumps('abc')))
# <class 'str'>
# >>> type(pickle.loads(pickle.dumps(True)))
# <class 'bool'>
