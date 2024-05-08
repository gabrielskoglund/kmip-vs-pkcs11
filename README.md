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
* [PKCS#11 using a REST API](./src/rest_api.py) - In order to evaluate an alternate
  transport method, this implementation uses a simple JSON-based REST API for singing operations.

All implementations use TLS 1.3 with mutual authentication.

In order to test the performance of the protocols without relying on real HMS or specific
cryptographic implementations, the servers use a ["mock HSM"](./src/mock_hsm.py) which
emulates a HSM that performs signatures in constant time and can be tuned for different
number of signatures per second.

## Running the experiments
The [experiment runner](./src/experiment_runner.py) can be used to run a set of experiments,
specified in JSON format. An example of such an experiment set can be seen in
the [`experiments.json` file](./src/experiments.json). A full JSON-schema is also available in
the experiment runner source code. The runner will perform all experiments from the given file
(by default `experiments.json`) and write output in CSV format to another file
(by default `results.csv`). Other locations can be specified using the `--experiments-file`
and `--output-file` command line options.

As an example, if the `experiments.json` file contains the following:
```json
{
    "experiments": [
        {
            "api": "kmip",
            "hsm_capacity": 1000,
            "num_signatures": 10000,
            "kmip_batch_count": 100,
            "threaded": false
        }
    ]
}
```
the command `python3 experiment_runner.py` will perform all experiments specified in
the `"experiments"` array. In this case this will be a single experiment where a KMIP
server will be started, using a mock HSM capable of performing 1000 signatures per
second. The time taken for a KMIP client to perform 10000 signatures using this server
will be timed, and the client will batch 100 signing requests in each message to the server.

### Output format
The experiment runner stores relevant information about each experiment in CSV format.
The fields in this format is in the following order:
* API used
* HSM capacity in (signatures per second)
* Number of signatures performed
* KMIP batch count (only present when using the KMIP API, otherwise left empty)
* Time taken (in seconds)
* Boolean indicating if threaded mode was used

For the example above, the output to the `results.csv` file might be something like:
```
kmip,1000,10000,100,36.754375431999506,False
```

### Experiments using different network conditions
When running the experiments on a Linux system, it is possible to use the
[`netem`](https://wiki.linuxfoundation.org/networking/netem) module to emulate
specific network conditions. This can be used to measure how the different APIs
perform depending on network latency. For example, to emulate a network latency
between client and server of 1 ms, running the command
```bash
sudo tc qdisc add dev lo root netem delay 1ms
```
will add a delay of 1ms to all traffic sent on the loopback interface,
affecting the traffic between client and server on the local network.
Note that this requires `sudo` privileges.

In order to remove this emulated delay once the experiments have been run,
the corresponding command is
```bash
sudo tc qdisc delete dev lo root netem
```
