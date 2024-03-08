FROM python:3.11.8

RUN apt-get update \
    && apt-get install -y \
        p11-kit \
        gnutls-bin \
        openssh-client \
    && pip install cryptography python-pkcs11 \
    && mkdir /root/.ssh

RUN mkdir -pm 0700 /run/user/0 && mkdir /run/user/0/p11-kit
ENV XDG_RUNTIME_DIR=/run/user/0

COPY --chmod=600 ssh_key.pub ssh_key /root/.ssh

RUN mkdir /experiment
COPY run.sh experiment /experiment

ENTRYPOINT [ "/experiment/run.sh" ]
