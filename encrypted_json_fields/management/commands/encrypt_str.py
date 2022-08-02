from django.core.management.base import BaseCommand
from encrypted_json_fields.fields import encrypt_str

import cryptography.fernet


class Command(BaseCommand):
    help = 'Encrypts an arbitrary string'

    def add_arguments(self, parser):
        parser.add_argument("text", type=str)

    def handle(self, *args, **options):
        value = encrypt_str(options['text'])
        self.stdout.write('"%s"' % value.decode('utf-8'))
