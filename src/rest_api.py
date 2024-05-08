import http.client
import http.server
import json
import logging
import socketserver
import ssl
from concurrent import futures
from http import HTTPStatus
from typing import Dict

import httpx

import auth.auth as auth
from common import DATA
from common import NUM_THREADS
from common import SIGNATURE_DATA
from common import PKCS11SessionStatus
from mock_hsm import MockHSM

REST_API_PORT = 50002

# Arbitrary constant handles
SESSION_HANDLE = 42
KEY_HANDLE = 1337


class PKCS11RESTClient:
    """
    PKCS11gRPCClient provides a simple interface for performing signing requests
    to a PKCS11RESTServer.
    """

    def __init__(self, threaded: bool = False):
        self.log = logging.getLogger(self.__class__.__name__)
        self.connection = httpx.Client(
            verify=self._get_ssl_context(),
        )
        self.threaded = threaded
        if threaded:
            self.thread_pool = futures.ThreadPoolExecutor(NUM_THREADS)

    def sign(self, num_signatures: int) -> None:
        """
        Perform simulated signature operations with a PKCS11RESTServer running on
        the local network.

        :param num_signatures: the number of signatures to perform.
        """
        self.log.debug(f"Beginning signing operations for {num_signatures} signatures")

        if self.threaded:
            fs = [
                self.thread_pool.submit(self._sign_single, session_handle=i)
                for i in range(num_signatures)
            ]
            futures.wait(fs, return_when=futures.ALL_COMPLETED)
            assert all([f.exception() is None for f in fs])

        else:
            for i in range(num_signatures):
                self._sign_single()

        self.log.debug("Signing operation complete")

    def _sign_single(self, session_handle: int = SESSION_HANDLE) -> None:
        res = self._send_json(
            {
                "session_handle": session_handle,
                "key_handle": KEY_HANDLE,
                "mechanism": "CKM_CKM_ECDSA_SHA256",
            },
            endpoint="sign_init",
        )
        assert res.status_code == HTTPStatus.OK

        res = self._send_json(
            {"session_handle": session_handle, "data": DATA.hex()}, endpoint="sign"
        )
        assert res.status_code == HTTPStatus.OK

        # Read signature as if were going to use it
        _ = bytes.fromhex(json.loads(res.content).get("signature"))

        self.log.debug("Successfully signed message")

    def _send_json(self, data: Dict, endpoint: str) -> httpx.Response:
        json_data = json.dumps(data)
        return self.connection.post(
            url=f"https://localhost:{REST_API_PORT}/{endpoint}",
            content=json_data,
            headers={"Content-type": "application/json"},
            timeout=None,
        )

    def _get_ssl_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        # Set up client authentication
        context.load_cert_chain(auth.CLIENT_CERT_PATH, auth.CLIENT_KEY_PATH)
        context.load_verify_locations(auth.ROOT_CERT_PATH)

        return context


class PKCS11RESTServer:
    """
    PKCS11RESTServer handles signing requests from a PKCS11RESTClient.

    :param hsm: The MockHSM to use for signing operations.
    """

    class _ThreadingServer(socketserver.TCPServer):
        """
        _ThreadingServer is a TCP server which can proces multiple requests
        concurrently.
        """

        def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
            self.thread_pool = futures.ThreadPoolExecutor(NUM_THREADS)

        # Note: owerwriting this method is a bit strange, but simply using the
        #       socketserver.ThreadingTCPServer would cause the requests to be
        #       handled in a sequential fashion, only using a new thread
        #       for each request.
        def _handle_request_noblock(self):
            self.thread_pool.submit(super()._handle_request_noblock)

    class _Handler(http.server.BaseHTTPRequestHandler):
        """
        _Handler handles incoming HTTP requests and is the class responsible
        for performing the actual PKCS#11 operations.
        """

        def log_request(self, code="-", size="-"):
            pass

        def do_POST(self) -> None:
            """
            Handle an incoming POST request.
            """
            path = self.path.split("/")[1]
            if path not in ["sign", "sign_init"]:
                self._error(HTTPStatus.NOT_FOUND, f"{path} is not a valid API endpoint")
                return

            body_len = int(self.headers.get("Content-Length", 0))
            body = self.request.read(body_len)
            try:
                request = json.loads(body)
            except json.decoder.JSONDecodeError:
                self._error(
                    HTTPStatus.BAD_REQUEST, "Request content must be valid JSON"
                )
                return

            if path == "sign_init":
                self._sign_init(request)
            elif path == "sign":
                self._sign(request)

        def _sign_init(self, request: Dict):
            session = request.get("session_handle")
            if session is None:
                self.server.log.debug("Missing request field: session_handle")
                self._error(
                    HTTPStatus.BAD_REQUEST, "Missing request field: session_handle"
                )
                return

            if (
                self.server.session_status.get(session)
                == PKCS11SessionStatus.SIGN_INITIALIZED
            ):
                self.server.log.debug(
                    "Invalid SignInit request, signing already in progress"
                )
                self._error(HTTPStatus.BAD_REQUEST, "Signing already initialized")
                return

            self.server.session_status[session] = PKCS11SessionStatus.SIGN_INITIALIZED
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            return

        def _sign(self, request):
            session = request.get("session_handle")
            if session is None:
                self.server.log.debug("Missing request field: session_handle")
                self._error(
                    HTTPStatus.BAD_REQUEST, "Missing request field: session_handle"
                )
                return

            if not (
                self.server.session_status.get(session)
                == PKCS11SessionStatus.SIGN_INITIALIZED
            ):
                self.server.log.debug("Invalid Sign request, signing not initialized")
                self._error(HTTPStatus.BAD_REQUEST, "Signing not initialized")
                return

            # Decode the data as if we were going to sign it
            data = request.get("data")
            if not data:
                self.server.log.debug("Missing request field: data")
                self._error("Missing request field: data")
                return
            _ = bytes.fromhex(data)

            self.server.hsm.sign()

            self.server.session_status[session] = PKCS11SessionStatus.READY
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            self.wfile.write(
                json.dumps({"signature": SIGNATURE_DATA.hex()}).encode("utf-8")
            )

        def _error(self, code: int, msg: str) -> None:
            self.send_response(code)
            self.end_headers()
            self.wfile.write(json.dumps({"error": msg}).encode("utf-8"))
            return

    def __init__(self, hsm: MockHSM, threaded: bool = False):
        self.log = logging.getLogger(self.__class__.__name__)

        if threaded:
            if not hsm.thread_safe:
                raise ValueError("Provided MockHSM must be thread safe")
            self.server = self._ThreadingServer(
                ("localhost", REST_API_PORT), self._Handler, bind_and_activate=False
            )
        else:
            self.server = socketserver.TCPServer(
                ("localhost", REST_API_PORT), self._Handler, bind_and_activate=False
            )

        self.server.socket = self._get_ssl_context().wrap_socket(
            self.server.socket, server_side=True, do_handshake_on_connect=True
        )
        self.server.allow_reuse_address = True
        self.server.session_status = {}
        self.server.log = logging.getLogger(self.server.__class__.__name__)
        self.server.hsm = hsm

    def serve(self):
        """
        Serve connections from PKCS11RESTClients on the local network.
        """
        self.log.debug(f"Server started, listening to localhost port {REST_API_PORT}")
        # We manually bind and activate the server to be able to set the
        # allow_reuse_address property (in __init__) before the socket is bound
        self.server.server_bind()
        self.server.server_activate()
        self.server.serve_forever()

    def _get_ssl_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Require client verification
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(auth.SERVER_CERT_PATH, auth.SERVER_KEY_PATH)
        context.load_verify_locations(auth.ROOT_CERT_PATH)

        return context
