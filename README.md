# KMIP vs PKCS#11 experimental setup

This repository contains code for testing and comparing the performance of the
[KMIP](https://en.wikipedia.org/wiki/KMIP) and
[PKCS#11](https://en.wikipedia.org/wiki/PKCS_11) protocols when used in a PKI context.

## Design overview
The envisaged scenario is that of a CA application communicating with a HSM over a network.
To emulate this, a client and server is implemented for the following:
* [KMIP](./src/kmip_api.py) - KMIP specifies the TTLV format as the default wire format,
  and this implementation uses the [PyKMIP](https://github.com/OpenKMIP/PyKMIP/)
  project for TTLV encoding/decoding.
* [PKCS#11 using gRPC](./src/grpc_api.py) - The PKCS#11 standard defines a C API, and does not
  specify a canonical way to use PKCS#11 over a network. This implementation uses
  the [gRPC](https://grpc.io/) protocol to transmit messages using protocol buffers.
* [PKCS#11 using a REST API] - In order to evaluate an alternate transport method, this
  implementation uses a simple JSON-based REST API for singing operations.

All implementations use TLS 1.3 with mutual authentication.

In order to test the performance of the protocols without relying on real HMS or specific
cryptographic implementations, the servers use a ["mock HSM"](./src/mock_hsm.py) which
emulates a HSM that performs signatures in constant time and can be tuned for different
number of signatures per second.
