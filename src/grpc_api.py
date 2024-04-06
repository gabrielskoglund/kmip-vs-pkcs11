import grpc
import logging
from enum import Enum
from concurrent import futures

import auth.auth as auth
import grpc_gen.pkcs11_pb2 as p11_pb
import grpc_gen.pkcs11_pb2_grpc as p11_grpc
from common import DATA
from common import SIGNATURE_DATA
from common import PKCS11SessionStatus
from mock_hsm import MockHSM

GRPC_PORT_NUMBER = 50001

# Arbitrary constant handles
SESSION_HANDLE = 42
KEY_HANDLE = 1337


class PKCS11gRPCClient:
    """
    PKCS11gRPCClient provides a simple interface for performing signing requests
    to a PKCS11gRPCServer.
    """

    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)
        self.stub = p11_grpc.PKCS11Stub(
            grpc.secure_channel(
                target=f"localhost:{GRPC_PORT_NUMBER}",
                credentials=self._get_credentials(),
            )
        )

    def sign(self, num_signatures: int) -> None:
        """
        Perform simulated signature operations with a PKCS11gRPCServer running on
        the local network.

        :param num_signatures: the number of signatures to perform.
        """
        if num_signatures < 0:
            raise ValueError("num_signatures must be a positive integer")

        self.log.debug(f"Beginning signing operations for {num_signatures} signatures")
        for i in range(num_signatures):
            res = self.stub.C_SignInit(
                p11_pb.SignInit(
                    session_handle=SESSION_HANDLE,
                    key_handle=KEY_HANDLE,
                    mechanism=p11_pb.CK_MECHANISM_TYPE.CKM_CKM_ECDSA_SHA256,
                )
            )
            assert res.return_value == p11_pb.CK_RV.CKR_OK

            res = self.stub.C_Sign(
                p11_pb.Sign(session_handle=SESSION_HANDLE, data=DATA)
            )
            assert res.return_value == p11_pb.CK_RV.CKR_OK
            self.log.debug("Successfully signed message")

        self.log.debug("Signing operation complete")

    def _get_credentials(self) -> grpc.ChannelCredentials:
        with open(auth.CLIENT_KEY_PATH, "rb") as f:
            key_pem = f.read()
        with open(auth.CLIENT_CERT_PATH, "rb") as f:
            cert_pem = f.read()
        with open(auth.ROOT_CERT_PATH, "rb") as f:
            root_cert_pem = f.read()

        return grpc.ssl_channel_credentials(
            certificate_chain=cert_pem,
            private_key=key_pem,
            root_certificates=root_cert_pem,
        )


class PKCS11Servicer(p11_grpc.PKCS11Servicer):
    """
    PKCS11Servicer provides a gRPC interface for simulated PKCS#11 signing operations.

    :param hsm: the MockHSM object to use when performing signing operations.
    """
    def __init__(self, hsm: MockHSM):
        super().__init__()
        self.log = logging.getLogger(self.__class__.__name__)
        self.hsm = hsm
        self.session_status = {}

    def C_SignInit(self, request, context):
        """
        Initialize a PKCS#11 signing operation.
        """
        self.log.debug("Received SignInit request")
        session = request.session_handle

        if self.session_status.get(session) == PKCS11SessionStatus.SIGN_INITIALIZED:
            self.log.debug("Invalid SignInit request, signing already in progress")
            return p11_pb.SignInitResponse(
                return_value=p11_pb.CK_RV.CKR_OPERATION_ACTIVE
            )

        self.session_status[session] = PKCS11SessionStatus.SIGN_INITIALIZED
        return p11_pb.SignInitResponse(return_value=p11_pb.CK_RV.CKR_OK)

    def C_Sign(self, request, context):
        """
        Sign single part data. C_SignInit must be called before calling
        this function.
        """
        self.log.debug("Received Sign request")
        session = request.session_handle

        if self.session_status.get(session) != PKCS11SessionStatus.SIGN_INITIALIZED:
            self.log.debug("Invalid Sign request, signing not initialized")
            return p11_pb.SignResponse(
                return_value=p11_pb.CK_RV.CKR_OPERATION_NOT_INITIALIZED
            )

        self.log.debug("Performing singning operation")
        self.hsm.sign()
        self.log.debug("Signing complete")

        self.session_status[session] = PKCS11SessionStatus.READY
        return p11_pb.SignResponse(
            return_value=p11_pb.CK_RV.CKR_OK, signature=SIGNATURE_DATA
        )


class PKCS11gRPCServer:
    """
    PKCS11gRPCServer handles signing requests from a PKCS11gRPCClient.

    :param hsm: The MockHSM to use for signing operations.
    """
    def __init__(self, hsm: MockHSM):
        self.log = logging.getLogger(self.__class__.__name__)
        # We use only one thread for the server since the API is not thread safe
        self.server = grpc.server(futures.ThreadPoolExecutor(1))
        self.server.add_secure_port(
            address=f"localhost:{GRPC_PORT_NUMBER}",
            server_credentials=self._get_credentials(),
        )
        p11_grpc.add_PKCS11Servicer_to_server(PKCS11Servicer(hsm), self.server)

    def serve(self):
        """
        Serve connections from PKCS11gRPCClients on the local network.
        """
        self.server.start()
        self.log.debug(
            f"Server started. Listening on localhost port {GRPC_PORT_NUMBER}"
        )
        self.server.wait_for_termination()

    def _get_credentials(self) -> grpc.ServerCredentials:
        with open(auth.SERVER_KEY_PATH, "rb") as f:
            key_pem = f.read()
        with open(auth.SERVER_CERT_PATH, "rb") as f:
            cert_pem = f.read()
        with open(auth.ROOT_CERT_PATH, "rb") as f:
            root_cert_pem = f.read()

        return grpc.ssl_server_credentials(
            private_key_certificate_chain_pairs=[(key_pem, cert_pem)],
            root_certificates=root_cert_pem,
            require_client_auth=True,
        )
