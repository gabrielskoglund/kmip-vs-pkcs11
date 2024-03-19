# KMIP vs PKCS#11 experimental setup

This repository contains code for testing and comparing the performance of the
[KMIP](https://en.wikipedia.org/wiki/KMIP) and
[PKCS#11](https://en.wikipedia.org/wiki/PKCS_11) protocols when used in a PKI context.

## Design overview
The experimental setup is designed around two Docker containers:
  * The ["HSM" container](./hsm) emulates a hardware security module and exposes both a KMIP
    and a PKCS#11 interface. The KMIP interface is provided by the server from the
    [PyKMIP](https://github.com/OpenKMIP/PyKMIP) project, and the PKCS#11 interface
    is provided using [SoftHSM](https://github.com/opendnssec/SoftHSMv2) together with
    [p11-kit](https://github.com/p11-glue/p11-kit) for setting up tunneling of PKCS#11
    traffic over SSH.
  * The ["CA" container](./ca) emulates a CA application which connects to the HSM
    in order to sign certificates.

The CA container also contains [code](./ca/experiment) for performing timing tests of
KMIP and PKCS#11 using different configurations.

The experiments are orchestrated via the ["experiment runner"](./runner/main.py)
which starts the containers and issues commands to the experiment script in the CA container.
The experiment runner is also responsible for emulating network conditions using the
[netem](https://wiki.linuxfoundation.org/networking/netem) Linux kernel module.
The configuration of all experiments to run are provided in JSON format, and an example of
this format can be seen in the [`experiments.json`](./runner/experiments.json) file.
Output is given in CSV format.

## Example usage
```bash
runner/main.py --experiments experiments.json --output-file results.csv --build
```
will first build the CA and HSM docker containers, and then run the experiments specified
in `experiments.json`, storing the results in `results.csv`.

```bash
runner/main.py \
    --experiments experiments.json \
    --output-file results.csv \
    --runner-debug \
    --container-debug
```
will launch the same experiment, without rebuilding the containers and providing debug output
from both the runner script and the CA container experiments.

For more usage information consult the output of `runner/main.py --help`.
