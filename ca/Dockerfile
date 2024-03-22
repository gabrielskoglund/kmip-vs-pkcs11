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
COPY p11/ssh_key.pub p11/ssh_key /root/.ssh/
RUN chmod 600 /root/.ssh/ssh_key*

# Install patched fork of PyKMIP
RUN pip install pip install git+https://github.com/gabrielskoglund/PyKMIP

# Set up PyKMIP client configuration files
COPY kmip/pykmip.conf kmip/client* kmip/ca_certificate.pem /etc/pykmip/

COPY run.sh experiment /experiment/

ENTRYPOINT [ "/experiment/run.sh" ]
