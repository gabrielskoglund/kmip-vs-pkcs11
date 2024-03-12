from abc import ABC, abstractmethod
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

# TODO: replace this data with a proper tbs cert (or several)
DATA = b"Hello there!"

# TODO: Make this configurable
NUM_SIGNATURES = 1000

class Protocol(ABC):
    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)
        self.set_up_complete = False

    @abstractmethod
    def set_up(self) -> None:
        pass

    @abstractmethod
    def run_tests(self) -> None:
        pass

    @classmethod
    def verify_signature(
        self, public_key_der: bytes, message: bytes, signature: bytes
    ) -> None:
        # Sanity check to make sure we can verify a signature from the HSM
        # without relying on the HSM for verification
        # TODO: Make sure that these signing params are relevant
        #       in the context of PKI
        load_der_public_key(public_key_der).verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA512(),
        )


class ProtocolNotSetUpException(Exception):
    pass
