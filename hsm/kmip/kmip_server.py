import logging
import sys
import warnings

from cryptography.utils import CryptographyDeprecationWarning

from kmip.services.server import KmipServer

# Ignore some annoying warnings about ciphers that we won't be using
# being deprecated
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


if __name__ == "__main__":
    if "-d" in sys.argv:
        logging.basicConfig(level=logging.DEBUG)

    with KmipServer() as server:
        server.serve()
