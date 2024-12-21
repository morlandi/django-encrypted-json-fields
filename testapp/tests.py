import datetime

import cryptography.fernet
import mock
from django.forms import ModelForm
from django.test import TestCase
from django.utils import timezone

from encrypted_json_fields import fields, helpers


from . import models


class TestModelTestCase(TestCase):
    def test_value(self):
        """
        python manage.py test testapp.tests.TestModelTestCase.test_value
        """
        test_date_today = datetime.date.today()
        test_date = datetime.date(2011, 1, 1)
        test_datetime = datetime.datetime(2011, 1, 1, 1, tzinfo=timezone.timezone.utc)
        inst = models.TestModel()

        inst.enc_char_field = "This is a test string!"

        inst.enc_text_field = "This is a test string2!"
        inst.enc_date_field = test_date
        inst.enc_datetime_field = test_datetime
        inst.enc_boolean_field = True
        inst.enc_integer_field = 123456789
        inst.enc_positive_integer_field = 123456789
        inst.enc_small_integer_field = 123456789
        inst.enc_positive_small_integer_field = 123456789
        inst.enc_big_integer_field = 9223372036854775807
        json_obj = {
            "str_value": "text",
            "int_value": 123,
            "float_value": 123.45,
            "bool_value": True,
            "list_value": [1, 2, "three", False, 5.0],
            "dict_value": {
                "aaa": "AAA",
                "bbb": "BBB",
                "inner": {
                    "one": 1,
                    "two": 2,
                },
            },
            "datetime_value": datetime.datetime(2020, 1, 1),
            "date_value": datetime.date(2020, 1, 2),
            "null_value": None,
        }
        inst.enc_json_field = json_obj
        inst.save()
        inst = models.TestModel.objects.get()
        self.assertEqual(inst.enc_char_field, "This is a test string!")
        self.assertEqual(inst.enc_text_field, "This is a test string2!")
        self.assertEqual(inst.enc_date_field, test_date)
        self.assertEqual(inst.enc_date_now_field, test_date_today)
        self.assertEqual(inst.enc_date_now_add_field, test_date_today)
        self.assertEqual(inst.enc_datetime_field, test_datetime)
        self.assertEqual(inst.enc_boolean_field, True)
        self.assertEqual(inst.enc_integer_field, 123456789)
        self.assertEqual(inst.enc_positive_integer_field, 123456789)
        self.assertEqual(inst.enc_small_integer_field, 123456789)
        self.assertEqual(inst.enc_positive_small_integer_field, 123456789)
        self.assertEqual(inst.enc_big_integer_field, 9223372036854775807)

        json_obj["datetime_value"] = "2020-01-01T00:00:00"
        json_obj["date_value"] = "2020-01-02"

        inst.refresh_from_db()
        self.assertEqual(inst.enc_json_field, json_obj)

        test_date = datetime.date(2012, 2, 1)
<<<<<<< Updated upstream
        test_datetime = datetime.datetime(2012, 1, 1, 2, tzinfo=timezone.utc)
        inst.enc_char_field = "This is another test string!"
        inst.enc_text_field = "This is another test string2!"
=======
        test_datetime = datetime.datetime(2012, 1, 1, 2, tzinfo=timezone.timezone.utc)
        inst.enc_char_field = 'This is another test string!'
        inst.enc_text_field = 'This is another test string2!'
>>>>>>> Stashed changes
        inst.enc_date_field = test_date
        inst.enc_datetime_field = test_datetime
        inst.enc_boolean_field = False
        inst.enc_integer_field = -123456789
        inst.enc_positive_integer_field = 0
        inst.enc_small_integer_field = -123456789
        inst.enc_positive_small_integer_field = 0
        inst.enc_big_integer_field = -9223372036854775806
        inst.enc_json_field = "Another string"
        inst.save()

        inst = models.TestModel.objects.get()
        self.assertEqual(inst.enc_char_field, "This is another test string!")
        self.assertEqual(inst.enc_text_field, "This is another test string2!")
        self.assertEqual(inst.enc_date_field, test_date)
        self.assertEqual(inst.enc_date_now_field, datetime.date.today())
        self.assertEqual(inst.enc_date_now_add_field, datetime.date.today())
        # be careful about sqlite testing, which doesn't support native dates
        if timezone.is_naive(inst.enc_datetime_field):
            inst.enc_datetime_field = timezone.make_aware(inst.enc_datetime_field, timezone.timezone.utc)
        self.assertEqual(inst.enc_datetime_field, test_datetime)
        self.assertEqual(inst.enc_boolean_field, False)
        self.assertEqual(inst.enc_integer_field, -123456789)
        self.assertEqual(inst.enc_positive_integer_field, 0)
        self.assertEqual(inst.enc_small_integer_field, -123456789)
        self.assertEqual(inst.enc_positive_small_integer_field, 0)
        self.assertEqual(inst.enc_big_integer_field, -9223372036854775806)
        self.assertEqual(inst.enc_json_field, "Another string")

        inst.save()
        inst = models.TestModel.objects.get()

    def test_unicode_value(self):
        inst = models.TestModel()
        inst.enc_char_field = "\xa2\u221e\xa7\xb6\u2022\xaa"
        inst.enc_text_field = "\xa2\u221e\xa7\xb6\u2022\xa2"
        inst.save()

        inst2 = models.TestModel.objects.get()
        self.assertEqual(inst2.enc_char_field, "\xa2\u221e\xa7\xb6\u2022\xaa")
        self.assertEqual(inst2.enc_text_field, "\xa2\u221e\xa7\xb6\u2022\xa2")

    @mock.patch("django.db.models.sql.compiler.SQLCompiler.get_converters")
    def test_raw_value(self, get_converters_method):
        get_converters_method.return_value = []

        inst = models.TestModel()
        inst.enc_char_field = "This is a test string!"
        inst.enc_text_field = "This is a test string2!"
        inst.enc_date_field = datetime.date(2011, 1, 1)
        inst.enc_datetime_field = datetime.datetime(2012, 2, 1, 1, tzinfo=timezone.timezone.utc)
        inst.enc_boolean_field = True
        inst.enc_integer_field = 123456789
        inst.enc_positive_integer_field = 123456789
        inst.enc_small_integer_field = 123456789
        inst.enc_positive_small_integer_field = 123456789
        inst.enc_big_integer_field = 9223372036854775807
        inst.enc_json_field = "A string"
        inst.save()

        d = models.TestModel.objects.values()[0]
        for key, value in d.items():
            if key == "id":
                continue
            if key == "enc_json_field" and value.startswith('"'):
                value = value[1:]
            self.assertEqual(value[:7], "gAAAAAB", f"{key} failed: {value}")

        inst.save()

        d = models.TestModel.objects.values()[0]

    def test_get_internal_type(self):
        enc_char_field = models.TestModel._meta.fields[1]
        enc_text_field = models.TestModel._meta.fields[2]
        enc_date_field = models.TestModel._meta.fields[3]
        enc_date_now_field = models.TestModel._meta.fields[4]
        enc_boolean_field = models.TestModel._meta.fields[7]
        enc_integer_field = models.TestModel._meta.fields[8]
        enc_positive_integer_field = models.TestModel._meta.fields[9]
        enc_small_integer_field = models.TestModel._meta.fields[10]
        enc_positive_small_integer_field = models.TestModel._meta.fields[11]
        enc_big_integer_field = models.TestModel._meta.fields[12]
        enc_json_field = models.TestModel._meta.fields[12]

        self.assertEqual(enc_char_field.get_internal_type(), "TextField")
        self.assertEqual(enc_text_field.get_internal_type(), "TextField")
        self.assertEqual(enc_date_field.get_internal_type(), "TextField")
        self.assertEqual(enc_date_now_field.get_internal_type(), "TextField")
        self.assertEqual(enc_boolean_field.get_internal_type(), "TextField")

        self.assertEqual(enc_integer_field.get_internal_type(), "TextField")
        self.assertEqual(enc_positive_integer_field.get_internal_type(), "TextField")
        self.assertEqual(enc_small_integer_field.get_internal_type(), "TextField")
        self.assertEqual(enc_positive_small_integer_field.get_internal_type(), "TextField")
        self.assertEqual(enc_big_integer_field.get_internal_type(), "TextField")
        self.assertEqual(enc_json_field.get_internal_type(), "TextField")

    def test_auto_date(self):
        enc_date_now_field = models.TestModel._meta.fields[4]
        self.assertEqual(enc_date_now_field.name, "enc_date_now_field")
        self.assertTrue(enc_date_now_field.auto_now)

        enc_date_now_add_field = models.TestModel._meta.fields[5]
        self.assertEqual(enc_date_now_add_field.name, "enc_date_now_add_field")
        self.assertFalse(enc_date_now_add_field.auto_now)

        self.assertFalse(enc_date_now_field.auto_now_add)
        self.assertTrue(enc_date_now_add_field.auto_now_add)

    def test_max_length_validation(self):
        class TestModelForm(ModelForm):
            class Meta:
                model = models.TestModel
                fields = ("enc_char_field",)

        f = TestModelForm(data={"enc_char_field": "a" * 200})
        self.assertFalse(f.is_valid())

        f = TestModelForm(data={"enc_char_field": "a" * 99})
        self.assertTrue(f.is_valid())

    def test_rotating_keys(self):
        key1 = cryptography.fernet.Fernet.generate_key()
        key2 = cryptography.fernet.Fernet.generate_key()

        with self.settings(EJF_ENCRYPTION_KEYS=key1):
            # make sure we update the crypter with the new key
            fields.DEFAULT_CRYPTER = helpers.build_default_crypter()

            test_date_today = datetime.date.today()
            test_date = datetime.date(2011, 1, 1)
            test_datetime = datetime.datetime(2011, 1, 1, 1, tzinfo=timezone.timezone.utc)
            inst = models.TestModel()
            inst.enc_char_field = "This is a test string!"
            inst.enc_text_field = "This is a test string2!"
            inst.enc_date_field = test_date
            inst.enc_datetime_field = test_datetime
            inst.enc_boolean_field = True
            inst.enc_integer_field = 123456789
            inst.enc_positive_integer_field = 123456789
            inst.enc_small_integer_field = 123456789
            inst.enc_positive_small_integer_field = 123456789
            inst.enc_big_integer_field = 9223372036854775807
            inst.enc_json_field = "A string"
            inst.save()

        # test that loading the instance from the database results in usable data
        # (since it uses the older key that's still configured)
        with self.settings(EJF_ENCRYPTION_KEYS=[key2, key1]):
            # make sure we update the crypter with the new key
            fields.DEFAULT_CRYPTER = helpers.build_default_crypter()

            inst = models.TestModel.objects.get()
            self.assertEqual(inst.enc_char_field, "This is a test string!")
            self.assertEqual(inst.enc_text_field, "This is a test string2!")
            self.assertEqual(inst.enc_date_field, test_date)
            self.assertEqual(inst.enc_date_now_field, test_date_today)
            self.assertEqual(inst.enc_date_now_add_field, test_date_today)
            # be careful about sqlite testing, which doesn't support native dates
            if timezone.is_naive(inst.enc_datetime_field):
                inst.enc_datetime_field = timezone.make_aware(inst.enc_datetime_field, timezone.timezone.utc)
            self.assertEqual(inst.enc_datetime_field, test_datetime)
            self.assertEqual(inst.enc_boolean_field, True)
            self.assertEqual(inst.enc_integer_field, 123456789)
            self.assertEqual(inst.enc_positive_integer_field, 123456789)
            self.assertEqual(inst.enc_small_integer_field, 123456789)
            self.assertEqual(inst.enc_positive_small_integer_field, 123456789)
            self.assertEqual(inst.enc_big_integer_field, 9223372036854775807)
            self.assertEqual(inst.enc_json_field, "A string")

            # save the instance to rotate the key
            inst.save()

        # test that saving the instance results in key rotation to the correct key
        with self.settings(
            EJF_ENCRYPTION_KEYS=[
                key2,
            ]
        ):
            # make sure we update the crypter with the new key
            fields.DEFAULT_CRYPTER = helpers.build_default_crypter()

            # test that loading the instance from the database results in usable data
            # (since it uses the older key that's still configured)
            inst = models.TestModel.objects.get()
            self.assertEqual(inst.enc_char_field, "This is a test string!")
            self.assertEqual(inst.enc_text_field, "This is a test string2!")
            self.assertEqual(inst.enc_date_field, test_date)
            self.assertEqual(inst.enc_date_now_field, test_date_today)
            self.assertEqual(inst.enc_date_now_add_field, test_date_today)
            # be careful about sqlite testing, which doesn't support native dates
            if timezone.is_naive(inst.enc_datetime_field):
                inst.enc_datetime_field = timezone.make_aware(inst.enc_datetime_field, timezone.timezone.utc)
            self.assertEqual(inst.enc_datetime_field, test_datetime)
            self.assertEqual(inst.enc_boolean_field, True)
            self.assertEqual(inst.enc_integer_field, 123456789)
            self.assertEqual(inst.enc_positive_integer_field, 123456789)
            self.assertEqual(inst.enc_small_integer_field, 123456789)
            self.assertEqual(inst.enc_positive_small_integer_field, 123456789)
            self.assertEqual(inst.enc_big_integer_field, 9223372036854775807)
            self.assertEqual(inst.enc_json_field, "A string")

        # test that the instance with rotated key is no longer readable using the old key
        with self.settings(
            EJF_ENCRYPTION_KEYS=[
                key1,
            ]
        ):
            # make sure we update the crypter with the new key
            fields.DEFAULT_CRYPTER = helpers.build_default_crypter()

            # test that loading the instance from the database results in usable data
            # (since it uses the older key that's still configured)
            # Note we need to only load the enc_char_field because loading date field types
            # results in conversion to python dates, which will be raise a ValidationError when
            # the field can't be properly decoded
            inst = models.TestModel.objects.only("enc_char_field").get()
            ### !!!
            # TODO: check this
            if False:
                fields.fetch_raw_field_value(inst, "enc_char_field")
                self.assertNotEqual(inst.enc_char_field, "This is a test string!")
                self.assertEqual(inst.enc_char_field[:5], "gAAAA")

        # reset the DEFAULT_CRYPTER since we screwed with the default configuration with this test
        fields.DEFAULT_CRYPTER = helpers.build_default_crypter()

    @mock.patch("django.db.connection.ops.integer_field_range")
    def test_integer_field_validators(self, integer_field_range):
        def side_effect(arg):
            # throw error as mysql does in this case
            if arg == "TextField":
                raise KeyError(arg)
            # benign return value
            return (None, None)

        integer_field_range.side_effect = side_effect

        class TestModelForm(ModelForm):
            class Meta:
                model = models.TestModel
                fields = ("enc_integer_field",)

        f = TestModelForm(data={"enc_integer_field": 99})
        self.assertTrue(f.is_valid())

        inst = models.TestModel()
        # Should be safe to call
        super(fields.EncryptedIntegerField, inst._meta.get_field("enc_integer_field")).validators

        # should fail due to error
        with self.assertRaises(Exception):
            super(fields.EncryptedNumberMixin, inst._meta.get_field("enc_integer_field")).validators


class TestSearchTestCase(TestCase):
    def test_search_by_str(self):
        obj = models.TestSearchableModel(char_field="Hello")
        obj.save()

        found_obj = models.TestSearchableModel.objects.filter(char_field="Hello").first()

        self.assertEqual(found_obj, obj)
        self.assertEqual(found_obj.char_field, "Hello")
        self.assertEqual(found_obj.enc_char_field, "Hello")

    def test_search_by_int(self):
        obj = models.TestSearchableModel(integer_field=42)
        obj.save()

        found_obj = models.TestSearchableModel.objects.filter(integer_field=42).first()

        self.assertEqual(found_obj, obj)
        self.assertEqual(found_obj.integer_field, 42)
        self.assertEqual(found_obj.enc_integer_field, 42)

    def test_search_by_date(self):
        the_date = datetime.date(2022, 12, 25)

        obj = models.TestSearchableModel(date_field=the_date)
        obj.save()

        found_obj = models.TestSearchableModel.objects.filter(date_field=the_date).first()

        self.assertEqual(found_obj, obj)
        self.assertEqual(found_obj.date_field, the_date)
        self.assertEqual(found_obj.enc_date_field, the_date)

    def test_search_negative_case(self):
        the_date = datetime.date(2022, 12, 25)
        obj = models.TestSearchableModel(char_field="Hello", integer_field=42, date_field=the_date)
        obj.save()

        self.assertFalse(models.TestSearchableModel.objects.filter(char_field="Goodbye").exists())
        self.assertFalse(models.TestSearchableModel.objects.filter(integer_field=88).exists())
        self.assertFalse(models.TestSearchableModel.objects.filter(date_field=datetime.date(2023, 1, 1)).exists())

    def test_search_valueslist(self):
        obj = models.TestSearchableModel(char_field="Hello")
        obj.save()

        values = (
            models.TestSearchableModel.objects.filter(char_field="Hello")
            .values_list("char_field", "enc_char_field")
            .first()
        )

        self.assertNotEqual(values[0], "Hello")  # illustrates values_list might not behave as expected

        self.assertEqual(values[1], "Hello")
