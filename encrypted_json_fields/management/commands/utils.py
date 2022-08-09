from django.apps import apps
from encrypted_json_fields.fields import EncryptedMixin, EncryptedJSONField


def scan_and_save_models(verbosity):
    for model in apps.get_models():
        if model_uses_encryption(model):
            n = model.objects.count()
            print('\n%s (%d)' % (model._meta.object_name, n))
            i = 0
            for obj in model.objects.iterator():
                done = False
                try:
                    obj.save()
                    done = True
                except:
                    pass
                i += 1
                if verbosity >= 2:
                    print('%d/%d' % (i, n))

def model_uses_encryption(model):
    for field in model._meta.fields:
        if issubclass(field.__class__, EncryptedMixin):
            return True
        if issubclass(field.__class__, EncryptedJSONField):
            return True
    return False
