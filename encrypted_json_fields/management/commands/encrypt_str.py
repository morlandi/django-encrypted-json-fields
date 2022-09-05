from django.core.management.base import BaseCommand
from encrypted_json_fields import crypter
#import cryptography.fernet


class Command(BaseCommand):
    help = 'Encrypts an arbitrary string'

    def add_arguments(self, parser):
        parser.add_argument("text", type=str)
        parser.add_argument("--key", type=str, help="Optional encryption key")

    def handle(self, *args, **options):

        # Sanity checks
        if crypter.encryption_disabled():
            raise Exception("Encryption has been disabled")

        value = crypter.encrypt_str(options['text'], keys=options['key'])
        self.stdout.write('"%s"' % value.decode('utf-8'))
