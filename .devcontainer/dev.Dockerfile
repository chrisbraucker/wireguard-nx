FROM devkitpro/devkita64:latest

ARG CUSER=devcontainer

RUN adduser --disabled-password $CUSER \
 && usermod -aG sudo $CUSER

USER root
