import sys
import signal
from django.db import transaction
from django.core.management.base import BaseCommand
from django.conf import settings
from .utils import scan_and_save_models

def signal_handler(signal, frame):
    sys.exit(0)


class Command(BaseCommand):
    help = 'Decrypts fields in existing models'

    def __init__(self, logger=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        signal.signal(signal.SIGINT, signal_handler)

    def handle(self, *args, **options):
        settings.FIELD_SKIP_ENCRYPTION = True
        settings.DECRYPTING_ALL_FIELDS = True
        with transaction.atomic():
            scan_and_save_models(options['verbosity'])
