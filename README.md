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
KMIP and PKCS#11 under different network conditions. At the moment this is controlled via
`docker-compose`, but the intention is to instead set up a custom controller for launching
and interacting with the containers.

## Example usage
```bash
EXPERIMENT_ARGS="kmip" docker-compose up --abort-on-container-exit
```
will launch a basic experiment, testing the time taken to create 1000 signatures using
the KMIP server.

```bash
EXPERIMENT_ARGS="pkcs11 --debug --delay 10" docker-compose up --abort-on-container-exit
```
will launch the same experiment, but instead using the PKCS#11 interface of the HSM with
an added delay of 10ms to each package sent from the CA, as well as providing debug output.

