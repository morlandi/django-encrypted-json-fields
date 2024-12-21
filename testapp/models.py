import django.db.models
from django.core.serializers.json import DjangoJSONEncoder

from encrypted_json_fields import fields


class TestModel(django.db.models.Model):
    enc_char_field = fields.EncryptedCharField(max_length=100)
    enc_text_field = fields.EncryptedTextField()
    enc_date_field = fields.EncryptedDateField(null=True)
    enc_date_now_field = fields.EncryptedDateField(auto_now=True, null=True)
    enc_date_now_add_field = fields.EncryptedDateField(auto_now_add=True, null=True)
    enc_datetime_field = fields.EncryptedDateTimeField(null=True)
    enc_boolean_field = fields.EncryptedBooleanField(default=True)
    enc_integer_field = fields.EncryptedIntegerField(null=True)
    enc_positive_integer_field = fields.EncryptedPositiveIntegerField(null=True)
    enc_small_integer_field = fields.EncryptedSmallIntegerField(null=True)
    enc_positive_small_integer_field = fields.EncryptedPositiveSmallIntegerField(null=True)
    enc_big_integer_field = fields.EncryptedBigIntegerField(null=True)
    enc_json_field = fields.EncryptedJSONField(null=False, blank=True, default=dict, encoder=DjangoJSONEncoder)


class TestSearchableModel(django.db.models.Model):
    enc_char_field = fields.EncryptedCharField(max_length=100)
    char_field = fields.EncryptedSearchField(salt="1234", encrypted_field_name="enc_char_field")

    enc_date_field = fields.EncryptedDateField(null=True)
    date_field = fields.EncryptedSearchField(salt="xyz", encrypted_field_name="enc_date_field")

    enc_integer_field = fields.EncryptedIntegerField(null=True)
    integer_field = fields.EncryptedSearchField(encrypted_field_name="enc_integer_field")
