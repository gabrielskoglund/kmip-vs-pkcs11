FROM python:3.11.8

RUN apt-get update \
    && apt-get install -y \
        p11-kit \
        gnutls-bin \
        openssh-client \
        iproute2 \
    && pip install cryptography python-pkcs11

# p11-kit uses the XDG_RUNTIME_DIR to store temporary files,
# so we need to make sure it is set up.
RUN mkdir -pm 0700 /run/user/0 && mkdir /run/user/0/p11-kit
ENV XDG_RUNTIME_DIR=/run/user/0

# Set up ssh keys for PKCS#11 forwarding with p11-kit
COPY --chmod=600 p11/ssh_key.pub p11/ssh_key /root/.ssh/

# Setting up PyKMIP is a little involved since we need to apply
# our own patch to enable batched requests
# TODO: Create a proper patched fork of PyKMIP and use that instead
COPY kmip/pykmip_batching.patch /
RUN git clone --single-branch https://github.com/OpenKMIP/PyKMIP \
    && cd PyKMIP \
    && git checkout cae5747a199ef13c62448b1b1ae4a36d8b12b144 \
    && git apply --ignore-whitespace /pykmip_batching.patch \
    && pip install . \
    && cd \
    && rm -rf PyKMIP pykmip_batching.patch

# Set up PyKMIP client configuration files
COPY kmip/pykmip.conf kmip/client* kmip/ca_certificate.pem /etc/pykmip/

COPY run.sh experiment /experiment/

ENTRYPOINT [ "/experiment/run.sh" ]
