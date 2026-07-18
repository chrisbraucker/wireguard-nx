FROM devkitpro/devkita64:latest

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    ccache \
    clang \
    clang-format \
    cppcheck \
    file \
    git \
    libclang-rt-dev \
    openssh-client \
    python3 \
    python3-pip \
    ripgrep \
    xxd \
 && apt-get -y autoremove --purge \
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ARG CUSER=devcontainer

RUN adduser --disabled-password $CUSER \
 && usermod -aG sudo $CUSER

USER ${CUSER}
ENV HOME=/home/${CUSER}
