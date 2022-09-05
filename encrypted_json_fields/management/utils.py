import json
from django.apps import apps
from django.db import connection
from encrypted_json_fields import helpers
from encrypted_json_fields.fields import EncryptedMixin, EncryptedJSONField


def scan_db(encrypt_fields, verbosity):
    with connection.cursor() as cursor:
        for model in apps.get_models():
            fields = _list_model_encryption_fields(model)
            if len(fields) > 0:
                n = model.objects.count()
                print('\n%s (%d)' % (model._meta.object_name, n))
                i = 0
                for row in model.objects.iterator():
                    _update_table_row(cursor, row, fields, encrypt_fields)
                    i += 1
                    if verbosity >= 2:
                        print('%d/%d' % (i, n))


def _update_table_row(cursor, row, fields, encrypt_fields):

    # Use model attributes to collect unencrypted values;
    # for JSONFields, serialize the result into a string
    values = []
    for field in fields:
        is_json_field = issubclass(field.__class__, EncryptedJSONField)
        value = getattr(row, field.name)
        if is_json_field:
            if encrypt_fields:
                value = helpers.encrypt_values(value)
            value = json.dumps(value)
        else:
            if encrypt_fields:
                value = helpers.encrypt_str(value).decode('utf-8')
        values.append(value)

    # example: 'update myapp_mymodel set field1=%s, field2=%s where id=%s'
    sql = 'update {table_name} set {field_list} where id=%s'.format(
        table_name=row._meta.app_label + '_' + row._meta.model_name,
        field_list=', '.join(['%s=%%s' % f.name for f in fields])
    )

    # We update the table row bypassing the Model to avoid (further) encryption
    cursor.execute(sql, values + [row.id, ])


def _list_model_encryption_fields(model):
    encryption_fields = []
    for field in model._meta.fields:
        if issubclass(field.__class__, EncryptedMixin) or \
        issubclass(field.__class__, EncryptedJSONField):
            encryption_fields.append(field)
    return encryption_fields
