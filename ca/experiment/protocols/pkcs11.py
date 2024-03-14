import timeit

import pkcs11
from pkcs11.mechanisms import Mechanism
from pkcs11.util.rsa import encode_rsa_public_key

from protocols.common import DATA, NUM_SIGNATURES, RSA_KEY_LENGTH
from protocols.protocol import Protocol, ProtocolNotSetUpException

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
            pkcs11.KeyType.RSA, RSA_KEY_LENGTH
        )
        self.log.debug("Successfully generated RSA keypair")

        sig = self.private_key.sign(DATA, mechanism=Mechanism.SHA256_RSA_PKCS)
        self.log.debug("Successfully signed data")

        self.verify_rsa_signature(encode_rsa_public_key(self.public_key), DATA, sig)
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

        time = timeit.timeit(closure, number=NUM_SIGNATURES, globals=globals())
        self.log.info(
            "Testing finished. Time for %d signatures: %f seconds", NUM_SIGNATURES, time
        )
        self.log.info("Average time per signature: %f seconds", time / NUM_SIGNATURES)
        self.log.debug("Testing complete")
