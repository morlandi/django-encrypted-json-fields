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

`django-encrypted-json-fields` extends the origin project `django-encrypted-model-fields`
by adding a specific support for JSONFields, with the following features:

- the encrypted data remains a valid JSON, so you can inherit from django.db.models.JSONField and all validations will still work
- if the data contains dictionaries, the keys are preserved so that the overall structure remains intact
- that is: we only encrypt the values

### Implementation notes

I opted to encrypt the repr() of the values, then apply eval() later only (after decrypting).

This is usefull to reconstruct **both the value and the type**; since JSON manages
only a few simple types, this naive solution just fits the bill.

## The crypter

All functions responsible for encryption/decryption (see below) require a `crypter`, which
can be obtained in a few ways:

- default crypter: assign a key or a list of keys to the `EJF_ENCRYPTION_KEYS` setting,
  and a default crypter will be build for you
- assigning a callable to the `EJF_ENCRYPTION_KEYS` setting, which in turn will
  return a list of keys as above
- invoke `build_crypter(keys)` explicitly, and pass the resulting object around

For the latter, the use case I had in mind was the need to keep the data in play text
on the server, and export encrypted data for a remote client, sharing a common key.

## Deferred get_crypter()

Since `EJF_ENCRYPTION_KEYS` setting now accepts a callable, which might very well
need to retrieve some data from the Django models, I had to postpone the call to
get_crypter() until all apps have been loaded.

As a side effect, now you can always and safely call the `generate_encryption_key`
management command (see below)

## App settings

EJF_ENCRYPTION_KEYS

    either a key, a list of keys, or a callable returning the list of keys to
    be used for building the default crypter

EJF_DISABLE_ENCRYPTION

    skip encryption when saving the model (save data unencrypted)

## Helpers

All function used internally when saving and reading Django models can also be
invoked explicitly to apply encryption/decryption to arbitrary strings or JSON
values.

A possible use case consists in serializing encrypted data to be sent to a remote
client.

| Function | Purpone |
| ----------- | ----------- |
| `generate_random_encryption_key()` | generate a key |
| `build_crypter(keys)` | given a list of keys (or a key) builds the corresponding crypter |
| `is_encrypted(s: Union[str, bytes]) -> bool `| Check if the given string (or bytes) is the result of an encryption |
| `encrypt_str(s: str, crypter=None) -> bytes` | Encrypts the given string applying either the supplied crypter or, in None, the default crypter |
| `decrypt_bytes(t: bytes, crypter=None) -> str` | Decrypts the given bytes and returns a string |
| `encrypt_values(data, crypter=None, json_skip_keys=None)` | Applyes encryption to a JSON-serializable object |
| `decrypt_values(data, crypter=None)` | reverses encrypt_values() |


## Managment commands

Some management commands are supplied; run with `--help` for detailed informations:

- generate_encryption_key
- encrypt_str
- decrypt_str
- encrypt_all_tables
- decrypt_all_tables


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


## Credits

- <https://gitlab.com/lansharkconsulting/django/django-encrypted-model-fields> has been shared by Scott Sharkey
- <https://github.com/foundertherapy/django-cryptographic-fields> has been shared by Dana Spiegel
