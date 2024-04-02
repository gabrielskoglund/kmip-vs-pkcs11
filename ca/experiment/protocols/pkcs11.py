import timeit
import hashlib

import pkcs11
from pkcs11.mechanisms import Mechanism
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.util.ec import encode_ec_public_key, encode_ecdsa_signature

from protocols.common import DATA, NUM_SIGNATURES, write_result
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

        if self.key_type == "rsa":
            self._create_rsa_signing_key()
            self.log.debug("Successfully generated RSA keypair")

            sig = self.private_key.sign(DATA, mechanism=self.mechanism)
            self.log.debug("Successfully signed data")

            self.verify_rsa_signature(encode_rsa_public_key(self.public_key), DATA, sig)
        else:
            self._create_p256_signing_key()
            self.log.debug("Successfully generated P-256 keypair")

            # SoftHSMv2 does not support ECDSA with hashing, so we need
            # to manually hash our data before sending it to the HSM.
            data = hashlib.sha256(DATA).digest()
            sig = self.private_key.sign(data, mechanism=self.mechanism)
            self.log.debug("Successfully signed data")

            sig = encode_ecdsa_signature(sig)
            self.verify_p256_signature(encode_ec_public_key(self.public_key), DATA, sig)

        self.log.debug("Successfully verified signed data")

        self.set_up_complete = True
        self.log.debug("Set up complete")

    def run_experiment(self) -> None:
        self.log.info(
            "Running PKCS#11 experiment with "
            + (
                f"{self.key_length} bit RSA key, "
                if self.key_type == "rsa"
                else "P-256 key, "
            )
            + f"RTT: {self.rtt_ms}ms"
        )
        if not self.set_up_complete:
            raise ProtocolNotSetUpException(
                "Please run the set_up method before running the experiment"
            )

        def closure():
            self.private_key.sign(
                hashlib.sha256(DATA).digest(), mechanism=self.mechanism
            )

        time = timeit.timeit(closure, number=NUM_SIGNATURES, globals=globals())
        self.log.info(
            "Experiment finished. Time for %d signatures: %f seconds",
            NUM_SIGNATURES,
            time,
        )
        self.log.info("Average time per signature: %f seconds", time / NUM_SIGNATURES)

        write_result(
            {
                "protocol": "pkcs11",
                "key_type": self.key_type,
                "key_length": self.key_length,
                "rtt_ms": self.rtt_ms,
                "num_signatures": NUM_SIGNATURES,
                "time_s": time,
            }
        )
        self.log.debug("Result written to file")

    def _create_rsa_signing_key(self):
        self.public_key, self.private_key = self.session.generate_keypair(
            pkcs11.KeyType.RSA, self.key_length
        )
        self.mechanism = Mechanism.SHA256_RSA_PKCS

    def _create_p256_signing_key(self):
        params = self.session.create_domain_parameters(
            pkcs11.KeyType.EC,
            {
                pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters(
                    "secp256r1"
                )
            },
            local=True,
        )
        self.public_key, self.private_key = params.generate_keypair()

        self.mechanism = Mechanism.ECDSA
