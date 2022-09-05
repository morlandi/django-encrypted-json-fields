from django.core.management.base import BaseCommand
from encrypted_json_fields import helpers


class Command(BaseCommand):
    help = 'Decrypts an arbitrary string'

    def add_arguments(self, parser):
        parser.add_argument("text", type=str)
        parser.add_argument("--key", type=str, help="Optional encryption key")

    def handle(self, *args, **options):

        # Sanity checks
        if helpers.encryption_disabled():
            raise Exception("Encryption has been disabled")

        crypter = helpers.build_crypter(options['key'])
        value = helpers.decrypt_bytes(options['text'].encode('utf-8'), crypter=crypter)
        self.stdout.write('"%s"' % value)
