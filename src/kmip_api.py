import logging
import socket
import ssl
import struct
import time

from kmip.core import attributes
from kmip.core import enums
from kmip.core import primitives
from kmip.core import utils
from kmip.core.messages import contents
from kmip.core.messages import messages
from kmip.core.messages import payloads

import auth.auth as auth
from common import DATA
from common import SIGNATURE_DATA
from mock_hsm import MockHSM

# Artbitrary key UUID
KEY_ID = "6b1a74fe-ef75-4272-ae4e-472c097fe397"

KMIP_PORT_NUMBER = 5696


class KMIPClient:
    """
    KMIPClient provides a simple interface for performing signing requests
    to a KMIPServer.

    :param simulated_rtt_ms: the round trip time to add for each network
    round trip, in order to simulate real network conditions.
    """

    def __init__(self, simulated_rtt_ms: float = 0):
        self.log = logging.getLogger(self.__class__.__name__)
        self.rtt_delay_s = simulated_rtt_ms / 1000

    def sign(self, num_signatures: int, batch_count: int) -> None:
        """
        Perform simulated signature operations with a KMIPServer running on
        the local network.

        :param num_signatures: the number of signatures to perform.
        :param batch_count: the number of signature operations to batch in
            each KMIP request message.
        """
        if num_signatures <= 0 or batch_count <= 0:
            raise ValueError(
                "Both num_messages and batch_count must be positive integers"
            )

        self.log.debug(
            f"Beginning signing operation with {num_signatures} messages "
            f"and batch count {batch_count}"
        )

        while num_signatures >= batch_count:
            self._handle_request(batch_count)
            num_signatures -= batch_count

        if num_signatures > 0:
            self._handle_request(num_signatures)

        self.log.debug("Signing operation complete")

    @classmethod
    def encode_request(cls, batch_count: int) -> bytes:
        """
        Encode a KMIP request message.

        :param batch_count: The number of signing requests to add to the message batch.
            Each request will contain the same dummy data.
        """
        header = messages.RequestHeader(
            protocol_version=contents.ProtocolVersion(2, 0),
            batch_count=contents.BatchCount(batch_count),
        )

        batch_items = []
        for item_no in range(batch_count):
            payload = payloads.SignRequestPayload(
                unique_identifier=KEY_ID,
                cryptographic_parameters=attributes.CryptographicParameters(
                    digital_signature_algorithm=enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA256
                ),
                data=DATA,
            )

            batch_items.append(
                messages.RequestBatchItem(
                    operation=primitives.Enumeration(
                        enums.Operation, enums.Operation.SIGN, tag=enums.Tags.OPERATION
                    ),
                    request_payload=payload,
                    unique_batch_item_id=contents.UniqueBatchItemID(item_no.to_bytes()),
                )
            )

        msg = messages.RequestMessage(request_header=header, batch_items=batch_items)
        stream = utils.BytearrayStream()
        msg.write(stream, kmip_version=enums.KMIPVersion.KMIP_2_0)
        return stream.readall()

    @classmethod
    def decode_response(cls, data: bytes) -> messages.ResponseMessage:
        """
        Decode a KMIP response message.

        :param data: the encoded KMIP message to decode.
        """
        msg = messages.ResponseMessage()
        msg.read(utils.BytearrayStream(data), enums.KMIPVersion.KMIP_2_0)
        return msg

    @classmethod
    def _get_ssl_context(cls):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        # Set up client authentication
        context.load_cert_chain(auth.CLIENT_CERT_PATH, auth.CLIENT_KEY_PATH)
        context.load_verify_locations(auth.ROOT_CERT_PATH)

        return context

    def _handle_request(self, batch_count=int) -> None:
        self.log.debug("Preparing new KMIP request")

        context = self._get_ssl_context()
        conn = context.wrap_socket(socket.socket(family=socket.AF_INET))
        conn.connect(("localhost", KMIP_PORT_NUMBER))
        self.log.debug("Connection to server successful")

        req = self.encode_request(batch_count)
        conn.sendall(req)
        self.log.debug(f"Sent KMIP request with batch count {batch_count}")

        # Read the message header from the KMIP response message
        header = conn.recv(8)
        msg_size = struct.unpack("!I", header[4:])[0]

        payload = conn.recv(msg_size)
        while len(payload) < msg_size:
            payload += conn.recv(msg_size - len(payload))

        res = self.decode_response(header + payload)
        self.log.debug(
            "Received KMIP response with batch count "
            f"{res.response_header.batch_count}"
        )

        for item in res.batch_items:
            assert item.result_status.value == enums.ResultStatus.SUCCESS

        # We simulate the round trip time between client and server
        # by sleeping for a set amount of time before returning.
        # TODO: also take into account the TLS establishment round trips
        time.sleep(self.rtt_delay_s)


class KMIPServer:
    """
    KMIPServer handles signing requests from a KMIPClient.

    :param hsm: the MockHSM object to use to perform signing operations.
    """

    def __init__(self, hsm: MockHSM):
        self.log = logging.getLogger(self.__class__.__name__)
        self.hsm = hsm

    def serve(self):
        """
        Serve connections from KMIPClients on the local network.
        """
        self.log.debug("Server started")
        context = self._get_ssl_context()

        sock = context.wrap_socket(
            socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0),
            server_side=True,
            do_handshake_on_connect=True,
        )
        sock.bind(("localhost", KMIP_PORT_NUMBER))
        sock.listen()
        self.log.debug(f"Listening to localhost at port {KMIP_PORT_NUMBER}")

        while True:
            conn, _ = sock.accept()
            self._handle_request(conn)

    @classmethod
    def decode_request(cls, data: bytes) -> messages.RequestMessage:
        """
        Decode a KMIP request message.

        :param data: the encoded KMIP message to decode.
        """
        msg = messages.RequestMessage()
        msg.read(utils.BytearrayStream(data), kmip_version=enums.KMIPVersion.KMIP_2_0)
        return msg

    @classmethod
    def encode_response(cls, batch_count: int) -> bytes:
        """
        Encode a KMIP response message.

        :param batch_count: The number of signing responses to add to the message batch.
            Each request will contain the same dummy signature.
        """
        header = messages.ResponseHeader(
            protocol_version=contents.ProtocolVersion(2, 0),
            time_stamp=contents.TimeStamp(),
            batch_count=contents.BatchCount(batch_count),
        )

        batch_items = []
        for item_no in range(batch_count):
            batch_items.append(
                messages.ResponseBatchItem(
                    operation=primitives.Enumeration(
                        enums.Operation, enums.Operation.SIGN, tag=enums.Tags.OPERATION
                    ),
                    result_status=contents.ResultStatus(enums.ResultStatus.SUCCESS),
                    response_payload=payloads.SignResponsePayload(
                        unique_identifier=KEY_ID, signature_data=SIGNATURE_DATA
                    ),
                    unique_batch_item_id=contents.UniqueBatchItemID(item_no.to_bytes()),
                )
            )

        msg = messages.ResponseMessage(response_header=header, batch_items=batch_items)
        stream = utils.BytearrayStream()
        msg.write(stream, kmip_version=enums.KMIPVersion.KMIP_2_0)
        return stream.readall()

    @classmethod
    def _get_ssl_context(cls) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Require client authentication
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(auth.SERVER_CERT_PATH, auth.SERVER_KEY_PATH)
        context.load_verify_locations(auth.ROOT_CERT_PATH)

        return context

    def _handle_request(self, conn: ssl.SSLSocket) -> None:
        self.log.debug("Accepted connection")

        # Read the message header from the KMIP message
        header = conn.recv(8)
        msg_size = struct.unpack("!I", header[4:])[0]

        payload = conn.recv(msg_size)
        while len(payload) < msg_size:
            payload += conn.recv(msg_size - len(payload))

        req = self.decode_request(header + payload)
        self.log.debug("Received client KMIP request message")

        batch_count = req.request_header.batch_count.value
        self.log.debug(f"Performing {batch_count} signatures")
        for i in range(batch_count):
            self.hsm.sign()
        self.log.debug("Signing complete")

        res = self.encode_response(batch_count)
        conn.send(res)
        self.log.debug("Sent KMIP response message")
