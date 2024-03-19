FROM python:3.11.8

RUN apt-get update && \
    apt-get install -y \
        gnutls-bin \
        softhsm \
        openssh-server \
        iproute2 \
        meson

# Build p11-kit from source since the Debian verion seems outdated
RUN wget https://github.com/p11-glue/p11-kit/releases/download/0.25.3/p11-kit-0.25.3.tar.xz \
    && tar -xvf p11-kit-0.25.3.tar.xz \
    && cd p11-kit-0.25.3 \
    && meson setup _build \
    && meson compile -C _build \
    && meson test -C _build \
    && meson install -C _build \
    && cd / \
    && rm -r p11-kit-0.25.3*

# p11-kit uses the XDG_RUNTIME_DIR to store temporary files,
# so we need to make sure it is set up.
RUN mkdir -pm 0700 /run/user/0 && mkdir /run/user/0/p11-kit
ENV XDG_RUNTIME_DIR=/run/user/0

# Set up ssh keys for PKCS#11 tunneling with p11-kit
COPY p11/ssh_key.pub /root/.ssh/authorized_keys

# We can use the packaged version of PyKMIP for the server since
# the KMIP server component already supports batching
RUN pip install PyKMIP
COPY kmip/server* kmip/ca_certificate.pem /etc/pykmip/

COPY run.sh kmip/kmip_server.py /

ENTRYPOINT [ "/run.sh" ]

