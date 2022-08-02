from django.core.management.base import BaseCommand
from encrypted_model_fields.fields import decrypt_str

import cryptography.fernet


class Command(BaseCommand):
    help = 'Decrypts an arbitrary string'

    def add_arguments(self, parser):
        parser.add_argument("text", type=str)

    def handle(self, *args, **options):
        value = decrypt_str(options['text'])
        self.stdout.write('"%s"' % value)