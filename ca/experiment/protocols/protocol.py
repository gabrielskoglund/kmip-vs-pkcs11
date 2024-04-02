from abc import ABC, abstractmethod
import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.hazmat.primitives.serialization import load_der_public_key


class Protocol(ABC):
    def __init__(self, rtt_ms: int, key_type: str, key_length: int):
        self.log = logging.getLogger(self.__class__.__name__)
        self.set_up_complete = False
        self.rtt_ms = rtt_ms
        self.key_type = key_type
        self.key_length = key_length

    @abstractmethod
    def set_up(self) -> None:
        pass

    @abstractmethod
    def run_experiment(self) -> None:
        pass

    @classmethod
    def verify_rsa_signature(
        self, public_key_der: bytes, message: bytes, signature: bytes
    ) -> None:
        # Sanity check to make sure we can verify a signature from the HSM
        # without relying on the HSM for verification
        load_der_public_key(public_key_der).verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    @classmethod
    def verify_p256_signature(
        self, public_key_der: bytes, message: bytes, signature: bytes
    ) -> None:
        pub = load_der_public_key(public_key_der)
        pub.verify(
            signature,
            message,
            signature_algorithm=ec.ECDSA(hashes.SHA256())
        )


class ProtocolNotSetUpException(Exception):
    pass
