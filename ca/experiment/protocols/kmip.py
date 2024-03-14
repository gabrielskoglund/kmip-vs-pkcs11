import timeit
from typing import List

from kmip.core import objects, enums
from kmip.core.attributes import CryptographicParameters
from kmip.core.factories.attributes import AttributeFactory
from kmip.core.messages.contents import UniqueBatchItemID
from kmip.services.kmip_client import KMIPProxy

from protocols.common import DATA, NUM_SIGNATURES, RSA_KEY_LENGTH
from protocols.protocol import Protocol, ProtocolNotSetUpException


class KMIP(Protocol):
    def set_up(self) -> None:
        self.log.debug("Set up started")
        self.attribute_factory = AttributeFactory()

        self.proxy = KMIPProxy(kmip_version=enums.KMIPVersion.KMIP_2_0)
        self.proxy.open()
        self.log.debug("Successfully opened proxy")

        self._create_rsa_signing_key()
        self.log.debug("Successfully generated RSA key pair")

        response = self.proxy.activate(self.private_key)
        if response.result_status.value != enums.ResultStatus.SUCCESS:
            raise Exception(f"Key activation failed: {response.result_message}")
        self.log.debug("Successfully activated private key")

        sig = self._sign([DATA])
        self.log.debug("Successfully signed data")

        response = self.proxy.get(self.public_key)
        if response.result_status.value != enums.ResultStatus.SUCCESS:
            raise Exception(f"Could not get public key: {response.result_message}")

        self.verify_rsa_signature(
            response.secret.key_block.key_value.key_material.value, DATA, sig[0]
        )
        self.log.debug("Successfully verified signature")

        self.set_up_complete = True
        self.log.debug("Set up complete")

    def run_tests(self) -> None:
        self.log.debug("Testing started")
        if not self.set_up_complete:
            raise ProtocolNotSetUpException(
                "Please run the set_up method before running the tests"
            )

        # TODO: Make configurable
        batch_size = 100
        batch = [DATA] * batch_size

        def closure():
            self._sign(batch)

        time = timeit.timeit(
            closure, number=NUM_SIGNATURES // batch_size, globals=globals()
        )
        self.log.info(
            "Testing finished. Time for %d signatures with a batch size of %d: %f seconds",
            NUM_SIGNATURES,
            batch_size,
            time,
        )
        self.log.info("Average time per signature: %f seconds", time / NUM_SIGNATURES)
        self.log.debug("Testing complete")

    def _create_rsa_signing_key(self):
        algorithm = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM,
            enums.CryptographicAlgorithm.RSA,
        )
        length = self.attribute_factory.create_attribute(
            enums.AttributeType.CRYPTOGRAPHIC_LENGTH, RSA_KEY_LENGTH
        )
        common_attributes = objects.TemplateAttribute(
            attributes=[algorithm, length],
            tag=enums.Tags.COMMON_TEMPLATE_ATTRIBUTE,
        )

        private_attributes = objects.TemplateAttribute(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [enums.CryptographicUsageMask.SIGN],
                )
            ],
            tag=enums.Tags.PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
        )

        public_attributes = objects.TemplateAttribute(
            attributes=[
                self.attribute_factory.create_attribute(
                    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK,
                    [enums.CryptographicUsageMask.VERIFY],
                )
            ],
            tag=enums.Tags.PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
        )

        response = self.proxy.create_key_pair(
            common_template_attribute=common_attributes,
            private_key_template_attribute=private_attributes,
            public_key_template_attribute=public_attributes,
        )

        if response.result_status.value != enums.ResultStatus.SUCCESS:
            raise Exception(f"Key creation failed: {response.result_message}")

        self.public_key = response.public_key_uuid
        self.private_key = response.private_key_uuid

    def _sign(self, messages: List[bytes]) -> List[bytes]:
        params = CryptographicParameters(
            digital_signature_algorithm=enums.DigitalSignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION,
            padding_method=enums.PaddingMethod.PKCS1v15,
        )

        for msg_num, msg in enumerate(messages):
            response = self.proxy.sign(
                msg,
                self.private_key,
                params,
                batch=True if msg_num < len(messages) - 1 else False,
                unique_batch_item_id=UniqueBatchItemID(value=msg_num),
            )

        if (
            isinstance(response, dict)
            and response["result_status"] != enums.ResultStatus.SUCCESS
        ):
            raise Exception(f"Signing failed: {response['result_message']}")

        if isinstance(response, dict):
            return [response["signature"]]

        # Ensure signatures are returned in the same order as the messages
        response.sort(key=lambda item: item["unique_identifier"])
        return [item["signature"] for item in response]
