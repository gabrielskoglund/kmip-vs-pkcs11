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

from mock_hsm import MockHSM
import auth.auth as auth

# This data is the DER encoded TBSCertificate bytes for a server TLS certificate.
# We use these in order to get a realistic amount of data to sign in the experiements.
DATA = bytes.fromhex(
    "3082064da003020102021007419e39583a4c76cf1ea14347fa5f3a300a06082a8648ce"
    "3d0403033056310b300906035504061302555331153013060355040a130c4469676943"
    "65727420496e633130302e06035504031327446967694365727420544c532048796272"
    "69642045434320534841333834203230323020434131301e170d323331303138303030"
    "3030305a170d3234313031363233353935395a3079310b300906035504061302555331"
    "1330110603550408130a43616c69666f726e6961311630140603550407130d53616e20"
    "4672616e636973636f31233021060355040a131a57696b696d6564696120466f756e64"
    "6174696f6e2c20496e632e3118301606035504030c0f2a2e77696b6970656469612e6f"
    "72673059301306072a8648ce3d020106082a8648ce3d030107034200043561f4211aff"
    "6ac43bfa0647c6196ebe7038f1dc16b1bc381412d4142b1c0b318159f567f6e72ad13c"
    "1efaaea7ed065dd66f5d894c6bc8b0e00f83cff5d38adaa38204d8308204d4301f0603"
    "551d230418301680140abc0829178ca5396d7a0ece33c72eb3edfbc37a301d0603551d"
    "0e04160414caac0c67a2e386433fbb43e741d9a1873a78dd33308202ed0603551d1104"
    "8202e4308202e0820f2a2e77696b6970656469612e6f7267820d77696b696d65646961"
    "2e6f7267820d6d6564696177696b692e6f7267820d77696b69626f6f6b732e6f726782"
    "0c77696b69646174612e6f7267820c77696b696e6577732e6f7267820d77696b697175"
    "6f74652e6f7267820e77696b69736f757263652e6f7267820f77696b69766572736974"
    "792e6f7267820e77696b69766f796167652e6f7267820e77696b74696f6e6172792e6f"
    "7267821777696b696d65646961666f756e646174696f6e2e6f72678206772e77696b69"
    "8212776d6675736572636f6e74656e742e6f726782112a2e6d2e77696b697065646961"
    "2e6f7267820f2a2e77696b696d656469612e6f726782112a2e6d2e77696b696d656469"
    "612e6f726782162a2e706c616e65742e77696b696d656469612e6f7267820f2a2e6d65"
    "64696177696b692e6f726782112a2e6d2e6d6564696177696b692e6f7267820f2a2e77"
    "696b69626f6f6b732e6f726782112a2e6d2e77696b69626f6f6b732e6f7267820e2a2e"
    "77696b69646174612e6f726782102a2e6d2e77696b69646174612e6f7267820e2a2e77"
    "696b696e6577732e6f726782102a2e6d2e77696b696e6577732e6f7267820f2a2e7769"
    "6b6971756f74652e6f726782112a2e6d2e77696b6971756f74652e6f726782102a2e77"
    "696b69736f757263652e6f726782122a2e6d2e77696b69736f757263652e6f72678211"
    "2a2e77696b69766572736974792e6f726782132a2e6d2e77696b69766572736974792e"
    "6f726782102a2e77696b69766f796167652e6f726782122a2e6d2e77696b69766f7961"
    "67652e6f726782102a2e77696b74696f6e6172792e6f726782122a2e6d2e77696b7469"
    "6f6e6172792e6f726782192a2e77696b696d65646961666f756e646174696f6e2e6f72"
    "6782142a2e776d6675736572636f6e74656e742e6f7267820d77696b6970656469612e"
    "6f7267821177696b6966756e6374696f6e732e6f726782132a2e77696b6966756e6374"
    "696f6e732e6f7267303e0603551d20043730353033060667810c010202302930270608"
    "2b06010505070201161b687474703a2f2f7777772e64696769636572742e636f6d2f43"
    "5053300e0603551d0f0101ff040403020388301d0603551d250416301406082b060105"
    "0507030106082b0601050507030230819b0603551d1f0481933081903046a044a04286"
    "40687474703a2f2f63726c332e64696769636572742e636f6d2f446967694365727454"
    "4c53487962726964454343534841333834323032304341312d312e63726c3046a044a0"
    "428640687474703a2f2f63726c342e64696769636572742e636f6d2f44696769436572"
    "74544c53487962726964454343534841333834323032304341312d312e63726c308185"
    "06082b0601050507010104793077302406082b060105050730018618687474703a2f2f"
    "6f6373702e64696769636572742e636f6d304f06082b06010505073002864368747470"
    "3a2f2f636163657274732e64696769636572742e636f6d2f4469676943657274544c53"
    "487962726964454343534841333834323032304341312d312e637274300c0603551d13"
    "0101ff04023000"
)

# This is the DER encoded signature of the data above, using ECDSA with
# SHA256 and a random elliptic curve key for curve P-256.
# We use this to get a realistic amount of data to return for each signing request.
SIGNATURE_DATA = bytes.fromhex(
    "3045022042f9d914581f438e7f3cf756a7ae5a34f9079bc658d33034f1660f8532fca0"
    "71022100a42b71e64de41d78a3fe7c0743e0a070e6b355ac393ab466430bf56f0da914"
    "d9"
)

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
        # Ensure that we are using TLS 1.3
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        # Set up client authentication
        context.load_cert_chain(auth.CLIENT_CERT_PATH, auth.CLIENT_KEY_PATH)
        context.load_verify_locations(auth.ROOT_CERT_PATH)
        context.post_handshake_auth = True

        return context

    def _handle_request(self, batch_count=int) -> None:
        self.log.debug("Preparing new KMIP request")

        context = self._get_ssl_context()
        conn = context.wrap_socket(socket.socket(family=socket.AF_INET))
        conn.connect(("localhost", KMIP_PORT_NUMBER))
        self.log.debug("Connection to server successful")

        # Note: We need to perform this extra read to get the client certificate
        # request from the server, the actual data recieved is irrelevant.
        # The certificate will be sent in the next message from the client.
        # For more details see `KMIPServer._handle_connection`.
        conn.read()
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
        # Ensure that we are using TLS 1.3
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        # Require client authentication
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(auth.SERVER_CERT_PATH, auth.SERVER_KEY_PATH)
        context.load_verify_locations(auth.ROOT_CERT_PATH)
        context.post_handshake_auth = True

        return context

    def _handle_request(self, conn: ssl.SSLSocket) -> None:
        self.log.debug("Accepted connection")

        # Note: the request for the client cert is sent in the next message
        # from the server to the client. For this reason we send a message
        # to the client before we handle any client data. If we didn't perform
        # this extra step, unauthenticated clients would be able to perform
        # a single request-response operation.
        # Ref: https://docs.python.org/3/library/ssl.html#tls-1-3 and
        # https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.verify_client_post_handshake
        conn.verify_client_post_handshake()
        conn.send(b"Certificate please :)")
        self.log.debug("Sent client cert request")

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
