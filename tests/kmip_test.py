from src.kmip_api import DATA, KEY_ID, KMIPClient, KMIPServer, SIGNATURE_DATA

from kmip.core import enums
from kmip.core.messages import contents


def test_request_encode_decode():
    msg = KMIPServer.decode_request(KMIPClient.encode_request(5))
    assert msg.request_header.protocol_version == contents.ProtocolVersion(2, 0)
    assert msg.request_header.batch_count == contents.BatchCount(5)
    assert len(msg.batch_items) == 5

    for item in msg.batch_items:
        assert item.operation.value == enums.Operation.SIGN

        payload = item.request_payload
        assert payload.unique_identifier == KEY_ID
        assert (
            payload.cryptographic_parameters.digital_signature_algorithm
            == enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA256
        )
        assert payload.data == DATA


def test_response_encode_decode():
    msg = KMIPClient.decode_response(KMIPServer.encode_response(5))
    assert msg.response_header.protocol_version == contents.ProtocolVersion(2, 0)
    assert msg.response_header.batch_count == contents.BatchCount(5)
    assert len(msg.batch_items) == 5

    for item in msg.batch_items:
        assert item.operation.value == enums.Operation.SIGN

        payload = item.response_payload
        assert payload.unique_identifier == KEY_ID
        assert payload.signature_data == SIGNATURE_DATA
