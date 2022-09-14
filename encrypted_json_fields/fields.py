import itertools
import json
import cryptography.fernet

import django.db
import django.db.models
from django.conf import settings
from django.core import validators
from django.utils import timezone
from django.db import connection
from django.utils.functional import cached_property
from django.core.serializers.json import DjangoJSONEncoder

from .helpers import encrypt_str
from .helpers import decrypt_bytes
from .helpers import encrypt_values
from .helpers import decrypt_values
from .helpers import is_encrypted


def fetch_raw_field_value(model_instance, fieldname):
    """
    Fetch the field value bypassing Django model,
    thus skipping any decryption
    """

    if connection.vendor in ['sqlite', ]:
        if type(model_instance.id) == int:
            id_filter = str(model_instance.id)
        else:
            id_filter = '"%s"' % str(model_instance.id).replace('-', '')
        sql = 'select %s from %s_%s where id=%s' % (
            fieldname, model_instance._meta.app_label, model_instance._meta.model_name, id_filter
        )
        params = None
    else:
        # i.e. 'postgresql'
        sql = 'select %s from %s_%s where id=%%s' % (fieldname, model_instance._meta.app_label, model_instance._meta.model_name)
        params = (model_instance.id, )

    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()

    return row[0]


class EncryptedMixin(object):
    def to_python(self, value):

        if value is None:
            return value

        if isinstance(value, (bytes, str)):
            # if isinstance(value, bytes):
            #     value = value.decode('utf-8')
            # try:
            #     value = decrypt_bytes(value)
            if is_encrypted(value):
                try:
                    value = decrypt_bytes(value.encode('utf-8'))
                except cryptography.fernet.InvalidToken:
                    pass

        return super(EncryptedMixin, self).to_python(value)

    def from_db_value(self, value, *args, **kwargs):
        return self.to_python(value)

    def get_db_prep_save(self, value, connection):
        value = super().get_db_prep_save(value, connection)
        if value is None:
            return value
        # decode the encrypted value to a unicode string, else this breaks in pgsql
        #return (encrypt_str(str(value))).decode('utf-8')
        value = str(value)
        return encrypt_str(value).decode('utf-8')

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


