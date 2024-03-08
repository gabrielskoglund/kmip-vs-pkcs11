import timeit

import pkcs11
from pkcs11.util.rsa import encode_rsa_public_key

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

from common import DATA, Protocol, ProtocolNotSetUpException

PKCS11_LIBRARY_PATH = "/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so"
TOKEN_LABEL = "token"
TOKEN_USER_PIN = "foobar"


class PKCS11(Protocol):
    def set_up(self) -> None:
        self.log.debug("Set up started")
        lib = pkcs11.lib(PKCS11_LIBRARY_PATH)

        self.token = lib.get_token(token_label=TOKEN_LABEL)
        self.log.debug("Successfully got token")

        self.session = self.token.open(user_pin=TOKEN_USER_PIN)
        self.log.debug("Successfully opened session")

        self.public_key, self.private_key = self.session.generate_keypair(
            pkcs11.KeyType.RSA, 2048
        )
        self.log.debug("Successfully generated RSA keypair")

        sig = self.private_key.sign(DATA)
        self.log.debug("Successfully signed data")

        # Sanity check to make sure we can verify the signature
        # without relying on the PKCS#11 library
        # TODO: Make sure that these signing params are relevant
        #       in the context of PKI
        load_der_public_key(encode_rsa_public_key(self.public_key)).verify(
            sig,
            DATA,
            padding.PKCS1v15(),
            hashes.SHA512(),
        )
        self.log.debug("Successfully verified signed data")

        self.set_up_complete = True
        self.log.debug("Set up complete")

    def run_tests(self) -> None:
        self.log.debug("Testing started")
        if not self.set_up_complete:
            raise ProtocolNotSetUpException(
                "Please run the set_up method before running the tests"
            )

        def closure():
            self.private_key.sign(DATA)

        time = timeit.timeit(closure, number=10_000, globals=globals())
        self.log.info("Testing finished. Time for 10 000 signatures: %f", time)
        self.log.info("Average time per signature: %f", time / 10_000)
