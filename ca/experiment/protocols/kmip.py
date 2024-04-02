import timeit

from kmip.core import enums
from kmip.pie.client import ProxyKmipClient

from protocols.common import DATA, NUM_SIGNATURES, write_result
from protocols.protocol import Protocol, ProtocolNotSetUpException


class KMIP(Protocol):
    def __init__(self, rtt_ms: int, batch_size: int, key_length: int):
        super().__init__(rtt_ms, key_length)
        self.batch_size = batch_size

    def set_up(self) -> None:
        self.log.debug("Set up started")

        self.client = ProxyKmipClient(kmip_version=enums.KMIPVersion.KMIP_2_0)
        self.client.open()
        self.log.debug("Successfully opened client connection")

        if self.key_type == "rsa":
            self._create_rsa_signing_key()
            self.log.debug("Successfully generated RSA key pair")
        else:
            self._create_p256_signing_key()
            self.log.debug("Successfully generated P256 key pair")

        self.client.activate(self.private_key)
        self.log.debug("Successfully activated private key")

        sig = self.client.sign(
            [DATA], uid=self.private_key, cryptographic_parameters=self.signing_params
        )
        self.log.debug("Successfully signed data")

        public_key_bytes = self.client.get(self.public_key)
        self.verify_rsa_signature(public_key_bytes.value, DATA, sig[0])
        self.log.debug("Successfully verified signature")

        self.set_up_complete = True
        self.log.debug("Set up complete")

    def run_experiment(self) -> None:
        self.log.info(
            f"Running KMIP experiment with {self.key_length} bit "
            f"{self.key_type.upper()} key, "
            f"batch size: {self.batch_size}, "
            f"RTT: {self.rtt_ms}ms"
        )
        if not self.set_up_complete:
            raise ProtocolNotSetUpException(
                "Please run the set_up method before running the experiment"
            )

        batch = [DATA] * self.batch_size

        def closure():
            self.client.sign(
                batch,
                uid=self.private_key,
                cryptographic_parameters=self.signing_params,
            )

        time = timeit.timeit(
            closure, number=NUM_SIGNATURES // self.batch_size, globals=globals()
        )
        self.log.info(
            "Experiment finished. Time for %d signatures with a batch size of %d: %f seconds",
            NUM_SIGNATURES,
            self.batch_size,
            time,
        )
        self.log.info("Average time per signature: %f seconds", time / NUM_SIGNATURES)

        write_result(
            {
                "protocol": "kmip",
                "key_type": "rsa",
                "key_length": self.key_length,
                "rtt_ms": self.rtt_ms,
                "kmip_batch_size": self.batch_size,
                "num_signatures": NUM_SIGNATURES,
                "time_s": time,
            }
        )
        self.log.debug("Result written to file")

    def _create_rsa_signing_key(self):
        public_key, private_key = self.client.create_key_pair(
            algorithm=enums.CryptographicAlgorithm.RSA,
            length=self.key_length,
            private_usage_mask=[enums.CryptographicUsageMask.SIGN],
            public_usage_mask=[enums.CryptographicUsageMask.VERIFY],
        )

        self.public_key = public_key
        self.private_key = private_key
        self.signing_params = {
            "cryptographic_algorithm": enums.CryptographicAlgorithm.RSA,
            "hashing_algorithm": enums.HashingAlgorithm.SHA_256,
            "padding_method": enums.PaddingMethod.PKCS1v15,
        }

    # TODO:
    def _create_p256_signing_key(self):
        raise NotImplementedError()
