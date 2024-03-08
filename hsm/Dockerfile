FROM python:3.11.8

RUN apt-get update && \
    apt-get install -y \
        gnutls-bin \
        softhsm \
        openssh-server \
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
    && rm -r p11-kit-0.25.3

RUN mkdir -pm 0700 /run/user/0 && mkdir /run/user/0/p11-kit
ENV XDG_RUNTIME_DIR=/run/user/0

COPY ssh_key.pub /root/.ssh/authorized_keys

COPY run.sh /

ENTRYPOINT [ "/run.sh" ]

