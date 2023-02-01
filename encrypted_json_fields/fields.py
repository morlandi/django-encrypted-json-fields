import hashlib
import itertools
import json
import string

import cryptography.fernet
import django.db
import django.db.models
from django.conf import settings
from django.core import validators
from django.core.exceptions import ImproperlyConfigured
from django.db import connection, models
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.text import capfirst

from .helpers import decrypt_bytes, decrypt_values, encrypt_str, encrypt_values, is_encrypted


def fetch_raw_field_value(model_instance, fieldname):
    """
    Fetch the field value bypassing Django model,
    thus skipping any decryption
    """

    if connection.vendor in [
        "sqlite",
    ]:
        if type(model_instance.id) == int:
            id_filter = str(model_instance.id)
        else:
            id_filter = '"%s"' % str(model_instance.id).replace("-", "")
        sql = "select %s from %s_%s where id=%s" % (
            fieldname,
            model_instance._meta.app_label,
            model_instance._meta.model_name,
            id_filter,
        )
        params = None
    else:
        # i.e. 'postgresql'
        sql = "select %s from %s_%s where id=%%s" % (
            fieldname,
            model_instance._meta.app_label,
            model_instance._meta.model_name,
        )
        params = (model_instance.id,)

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
                    value = decrypt_bytes(value.encode("utf-8"))
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
        # return (encrypt_str(str(value))).decode('utf-8')
        value = str(value)
        return encrypt_str(value).decode("utf-8")

    def get_internal_type(self):
        return "TextField"

    def deconstruct(self):
        name, path, args, kwargs = super(EncryptedMixin, self).deconstruct()

        if "max_length" in kwargs:
            del kwargs["max_length"]

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
            value = "1"
        elif value is False:
            value = "0"
        # decode the encrypted value to a unicode string, else this breaks in pgsql
        return encrypt_str(str(value)).decode("utf-8")


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
    description = (
        "An IntegerField that is encrypted before " "inserting into a database using the python cryptography " "library"
    )
    pass


class EncryptedPositiveIntegerField(EncryptedNumberMixin, django.db.models.PositiveIntegerField):
    pass


class EncryptedSmallIntegerField(EncryptedNumberMixin, django.db.models.SmallIntegerField):
    pass


class EncryptedPositiveSmallIntegerField(EncryptedNumberMixin, django.db.models.PositiveSmallIntegerField):
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
            # return json.loads(value, cls=self.decoder)
            # Deserialize the JSON,
            # then decrypt the values of the resulting object
            obj = json.loads(value, cls=self.decoder)
            return decrypt_values(obj)
        except json.JSONDecodeError:
            return value


SEARCH_HASH_PREFIX = "xZZx"


def is_hashed_already(data_string: str) -> bool:
    """
    Determines if the provided string is already a hash.

    Args:
        data_string (str): The data to evaluate.

    Returns:
        bool: Whether the data is already hashed.
    """

    if data_string is None:
        return False

    if not isinstance(data_string, str):
        return False

    if not data_string.startswith(SEARCH_HASH_PREFIX):
        return False

    actual_hash = data_string[len(SEARCH_HASH_PREFIX) :]

    if len(actual_hash) != 64:
        return False

    return all([char in string.hexdigits for char in actual_hash])


class EncryptedSearchFieldDescriptor:
    """
    Descriptor class for EncryptedSearchField.
    """

    def __init__(self, field):
        self.field = field

    def __get__(self, instance, owner):
        """
        Gets the underlying plaintext value from the encrypted field.
        """

        if instance is None:
            return self

        if self.field.encrypted_field_name in instance.__dict__:
            decrypted_data = instance.__dict__[self.field.encrypted_field_name]
        else:
            instance.refresh_from_db(fields=[self.field.encrypted_field_name])
            decrypted_data = getattr(instance, self.field.encrypted_field_name)

        # swap data from encrypted_field to search_field
        setattr(instance, self.field.name, decrypted_data)

        return instance.__dict__[self.field.name]

    def __set__(self, instance, value):
        """
        Updates the value on the corresponding encrypted field.
        """

        instance.__dict__[self.field.name] = value
        if not is_hashed_already(value):
            # if the value has been hashed already, don't pass the value to encrypted_field.
            # otherwise will overwrite the real data with an encrypted version of the hash!!
            instance.__dict__[self.field.encrypted_field_name] = value


class EncryptedSearchField(models.CharField):
    """
    A Search field to accompany an Encrypted Field. A keyed hash of the value is stored and searched against.

    The user provided hash_key should be suitably long and random to prevent being able to 'guess' the value
    The user must provide an encrypted_field_name of the corresponding encrypted-data field in the same model.

    Notes:
         - Do not use model.objects.update() unless you update both the SearchField and the associated EncryptedField.
         - Always add a SearchField to a model, don't change/alter an existing regular django field.
         - If using values_list, use the encrypted field, not the search field.
         - To be searchable, the same salt value must be maintained model wide; to change the salt; data needs to be re-saved.

    Note on Defaults:
        To make sure the expected 'default=' value is used (in both SearchField and EncryptedField),
        the SearchField must always use the EncryptedField's 'default=' value.
        This ensures the correct default is used in both fields for:
        1. Initial values in forms
        2. Migrations (adding defaults to existing rows)
        3. Saving model instances
        Having different defaults on the SearchField and Encrypted field, eg only setting
        default on one of them, leads to some unexpected and strange behaviour.
    """

    description = "A secure SearchField to accompany an EncryptedField"
    descriptor_class = EncryptedSearchFieldDescriptor

    def __init__(self, salt=None, encrypted_field_name=None, *args, **kwargs):
        if salt is None:
            self.salt = getattr(settings, "SEARCH_FIELD_SALT", "")
        else:
            self.salt = salt

        if encrypted_field_name is None:
            raise ImproperlyConfigured(
                "You must supply the name of the accompanying Encrypted Field that will hold the data"
            )
        if not isinstance(encrypted_field_name, str):
            raise ImproperlyConfigured("'encrypted_field_name' must be a string")

        self.encrypted_field_name = encrypted_field_name

        if kwargs.get("primary_key"):
            raise ImproperlyConfigured("SearchField does not support primary_key=True.")

        if "default" in kwargs:
            # We always use EncryptedField's default.
            raise ImproperlyConfigured(
                f"SearchField does not support 'default='. Set 'default=' on '{self.encrypted_field_name}' instead"
            )

        kwargs["max_length"] = 64 + len(SEARCH_HASH_PREFIX)  # will be sha256 hex digest
        kwargs["null"] = True  # should be nullable, in case data field is nullable.
        kwargs["blank"] = True  # to be consistent with 'null'. Forms are not based on SearchField anyway.
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        # Only include kwarg if it's not the default (None)
        if self.salt:
            kwargs["salt"] = self.salt

        if self.encrypted_field_name:
            kwargs["encrypted_field_name"] = self.encrypted_field_name

        return name, path, args, kwargs

    def contribute_to_class(self, cls, name, **kwargs):
        super().contribute_to_class(cls, name, **kwargs)
        setattr(cls, self.name, self.descriptor_class(self))

    def has_default(self):
        """Always use the EncryptedFields default"""
        return self.model._meta.get_field(self.encrypted_field_name).has_default()

    def get_default(self):
        """Always use EncryptedField's default."""
        return self.model._meta.get_field(self.encrypted_field_name).get_default()

    def get_prep_value(self, value):
        if value is None:
            return value
        # coerce to str before encoding and hashing

        # NOTE: not sure what happens when the str format for date/datetime is changed??
        # Should not matter as we are dealing with a datetime object in this case.
        # Eg str(datetime(10, 9, 2020))
        value = str(value)

        if is_hashed_already(value):
            # if we have hashed this previously, don't do it again
            return value

        salt = self.salt
        if callable(salt):
            salt = salt()

        salted_value = value + salt
        return SEARCH_HASH_PREFIX + hashlib.sha256(salted_value.encode()).hexdigest()

    def clean(self, value, model_instance):
        """
        Validate value against the validators from self.encrypted_field_name.
        Any validators on SearchField will be ignored.

        SearchField's 'max_length' constraint will still be enforced at the database
        level, but applied to the saved hash value.
        """
        if model_instance is None:
            # This will happen when calling manage.py createuser/createsuperuser
            return value

        return model_instance._meta.get_field(self.encrypted_field_name).clean(value, model_instance)

    def formfield(self, **kwargs):
        """
        Gets the FormField to use for this field; returns the one from the associated
        EncryptedField.
        """

        encfield_kwargs = kwargs.copy()

        if encfield_kwargs.get("label") is None:
            encfield_kwargs.update({"label": capfirst(self.verbose_name)})

        encfield_kwargs.pop("widget", None)

        return self.model._meta.get_field(self.encrypted_field_name).formfield(**encfield_kwargs)
