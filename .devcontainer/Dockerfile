FROM devkitpro/devkita64:latest

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gpg \
 && install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/llvm.gpg \
 && echo "deb [signed-by=/etc/apt/keyrings/llvm.gpg] https://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-16 main" \
    > /etc/apt/sources.list.d/llvm-16.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    ccache \
    clang-16 \
    clang-format-16 \
    cppcheck \
    file \
    git \
    libclang-rt-16-dev \
    openssh-client \
    python3 \
    python3-pip \
    ripgrep \
    xxd \
 && apt-get -y autoremove --purge \
 && apt-get -y clean \
 && ln -sf /usr/bin/clang-16 /usr/local/bin/clang \
 && ln -sf /usr/bin/clang++-16 /usr/local/bin/clang++ \
 && ln -sf /usr/bin/clang-format-16 /usr/local/bin/clang-format \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ARG CUSER=devcontainer

RUN adduser --disabled-password $CUSER \
 && usermod -aG sudo $CUSER \
 && sed -ri '/^%sudo[[:space:]]+ALL=/c\%sudo ALL=(ALL:ALL) NOPASSWD: ALL' /etc/sudoers

USER ${CUSER}
ENV HOME=/home/${CUSER}
