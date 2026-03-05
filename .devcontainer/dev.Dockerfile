FROM devkitpro/devkita64:latest

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client ccache man \
 && apt-get -y autoremove --purge \
 && apt-get -y clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ARG CUSER=devcontainer

RUN adduser --disabled-password $CUSER \
 && usermod -aG sudo $CUSER

USER root
