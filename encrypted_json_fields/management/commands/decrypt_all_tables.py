import sys
import signal
from django.db import transaction
from django.core.management.base import BaseCommand
from django.conf import settings
from encrypted_json_fields import helpers
from ..utils import scan_db


def signal_handler(signal, frame):
    sys.exit(0)


class Command(BaseCommand):
    help = 'Scan all tables and decrypt all encryptable fields'

    def __init__(self, logger=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        signal.signal(signal.SIGINT, signal_handler)

    def handle(self, *args, **options):

        # Sanity checks
        if helpers.encryption_disabled():
            raise Exception("Encryption has been disabled")
        assert helpers.get_default_crypter()

        with transaction.atomic():
            scan_db(encrypt_fields=False, verbosity=options['verbosity'])
