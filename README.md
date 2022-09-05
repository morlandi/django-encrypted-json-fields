# Django Encrypted Model Fields (including JSONField)

## About

This is a fork of <https://gitlab.com/lansharkconsulting/django/django-encrypted-model-fields>,
which in turn was a fork of <https://github.com/foundertherapy/django-cryptographic-fields>.

It has been renamed, and updated to properly support Python3 and the latest
versions of Django.

`django-encrypted-json-fields` is set of fields that wrap standard
Django fields with encryption provided by the python cryptography
library. These fields are much more compatible with a 12-factor design
since they take their encryption key from the settings file instead of a
file on disk used by `keyczar`.

While keyczar is an excellent tool to use for encryption, it's not
compatible with Python 3, and it requires, for hosts like Heroku, that
you either check your key file into your git repository for deployment,
or implement manual post-deployment processing to write the key stored
in an environment variable into a file that keyczar can read.

## JSONField support

`django-encrypted-json-fields` adds a specific support for JSONFields,
with the following features:

- The encrypted data remains a valid JSON, so you can inherit from django.db.models.JSONField and all validations will still work
- if the data contains dictionaries, the keys are preserved so that the overall structure remains intact
- we only encrypt the values

### Implementation notes

I opted to encrypt the repr() of the values, then apply eval() later only (after decrypting).

This is required to reconstruct **both the value and the type**.

Since JSON manages only a few simple types, this naive solution seems enough.

## Deferred get_crypter()

The `EJF_ENCRYPTION_KEYS` setting now accepts a callable.

Since the callable might need to retrieve some data from the Django models,
I had to postpone the call to get_crypter() until all apps have been loaded.

As a side effect, now you can always and safely call the `generate_encryption_key`
management command (see below)

## Overridding the Crypter

All functions responsible for encryption/decryption now accept an optional `crypter`
parameter which, when supplied, is used instead of `EJF_ENCRYPTION_KEYS`:

    - def encrypt_str(s, crypter=None)
    - def decrypt_str(t, crypter=None)
    - def encrypt_values(data, crypter=None, skip_keys=None)
    - def decrypt_values(data, crypter=None)

The use case I had in mind for this was the need to keep the data in clear on the server,
and export encrypted data for a remote client, sharing a common key.

## App settings

EJF_ENCRYPTION_KEYS

    either a key, a list of keys, or a callable returning the list of keys to
    be used for encryption

EJF_DISABLE_ENCRYPTION

    skip encryption when saving the model (save data unencrypted)

## Utilities

Some management commands are supplied; run with `--help` for detailed informations:

- generate_encryption_key
- encrypt_str
- decrypt_str
- encrypt_all_fields
- decrypt_all_fields

## Generating an Encryption Key

There is a Django management command `generate_encryption_key` provided
with the `encrypted_json_fields` library. Use this command to generate
a new encryption key to set as `settings.FIELD_ENCRYPTION_KEY`:

    ./manage.py generate_encryption_key

Running this command will print an encryption key to the terminal, which
can be configured in your environment or settings file.

~~NOTE: This command will ONLY work in a CLEAN, NEW django project that
does NOT import encrypted_json_fields in any of it's apps.~~ IF you are
already importing encrypted_json_fields, try running this in a python
shell instead:

    import os
    import base64

    new_key = base64.urlsafe_b64encode(os.urandom(32))
    print(new_key)

## Getting Started

> $ pip install django-encrypted-json-fields

Add "encrypted_json_fields" to your INSTALLED_APPS setting like this:

```
    INSTALLED_APPS = (
        ...
        'encrypted_json_fields',
    )
```

`django-encrypted-json-fields` expects the encryption key to be
specified using `FIELD_ENCRYPTION_KEY` in your project's `settings.py`
file. For example, to load it from the local environment:

```
    import os

    FIELD_ENCRYPTION_KEY = os.environ.get('FIELD_ENCRYPTION_KEY', '')
```

To use an encrypted field in a Django model, use one of the fields from
the `encrypted_json_fields` module:

```
    from encrypted_json_fields.fields import EncryptedCharField

    class EncryptedFieldModel(models.Model):
        encrypted_char_field = EncryptedCharField(max_length=100)
```

For fields that require `max_length` to be specified, the `Encrypted`
variants of those fields will automatically increase the size of the
database field to hold the encrypted form of the content. For example, a
3 character CharField will automatically specify a database field size
of 100 characters when `EncryptedCharField(max_length=3)` is specified.

Due to the nature of the encrypted data, filtering by values contained
in encrypted fields won't work properly. Sorting is also not supported.

## Running Tests

Does the code actually work?

Running the unit tests from this app:

```
python manage.py test -v 2
```

or

```
./runtests.py
```

or

```
coverage run --source='.' runtests.py
coverage report
```

Running the unit tests from your project:

```
python manage.py test -v 2 encrypted_json_fields --settings=encrypted_json_fields.testapp.settings
```


## Credits

- <https://gitlab.com/lansharkconsulting/django/django-encrypted-model-fields> has been shared by Scott Sharkey
- <https://github.com/foundertherapy/django-cryptographic-fields> has been shared by Dana Spiegel
