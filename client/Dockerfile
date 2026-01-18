# Build the TPM simulator using CMake from a regular Ubuntu container
FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

# Install some basic tools we're going to need to build the simulator.
# Put this first so local docker will cache this step before copying in the code that
# will get built.  This saves a lot of time on Windows development hosts.
# Install OpenSSH (useful for GitHub Actions that need to authenticate to
# private Git repositories) and gcovr (for generating code coverage reports)
# Install zip so we can zip up coverage reports.
RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  curl \
  gcc \
  git \
  libssl-dev \
  openssh-client \
  pipx \
  pkg-config \
  wget \
  zip \
  && rm -rf /var/lib/apt/lists/*
RUN pipx install gcovr

# Install .NET 8
RUN apt-get update && apt-get install -y dotnet-sdk-8.0

# copy the source tree into a temporary build tree.
WORKDIR /build
RUN git clone https://github.com/TrustedComputingGroup/TPM.git .

# enable building with code coverage
ENV CFLAGS=--coverage

################################################################################
# OpenSSL-based simulators
################################################################################

# Ubuntu 22.04 comes with OpenSSL 3
# After the build, delete everything but the files needed for coverage analysis
RUN mkdir -p /simulators/openssl3 && \
  cd /simulators/openssl3 && \
  cp -r /build/TPMCmd/* . && \
  cmake -S . -B DebugLinuxOpenSSL3 && \
  cmake --build DebugLinuxOpenSSL3 --parallel && \
  find . -type f -not -regex '.*Simulator\|.*\.gcno\|.*\.c\|.*\.h' -exec rm {} \; && \
  ln -s ./DebugLinuxOpenSSL3/Simulator/Simulator tpm2-simulator

# Roll back to OpenSSL 1.1 and build again
# After the build, delete everything but the files needed for coverage analysis
RUN if [ $(arch) = "x86_64" ]; then \
    LIBSSL_DEB_PATH=http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1-1ubuntu2.1~18.04.23_amd64.deb; \
    LIBSSL_DEV_DEB_PATH=http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1-1ubuntu2.1~18.04.23_amd64.deb; \
  else \
    LIBSSL_DEB_PATH=http://ports.ubuntu.com/pool/main/o/openssl/libssl1.1_1.1.1-1ubuntu2.1~18.04.23_arm64.deb; \
    LIBSSL_DEV_DEB_PATH=http://ports.ubuntu.com/pool/main/o/openssl/libssl-dev_1.1.1-1ubuntu2.1~18.04.23_arm64.deb; \
  fi && \
  mkdir -p /ossl1 && \
  cd /ossl1 && \
  wget ${LIBSSL_DEB_PATH} -O libssl.deb && \
  dpkg -i libssl.deb && \
  wget ${LIBSSL_DEV_DEB_PATH} -O libssl-dev.deb && \
  dpkg -i libssl-dev.deb

RUN mkdir -p /simulators/openssl1 && \
  cd /simulators/openssl1 && \
  cp -r /build/TPMCmd/* . && \
  cmake -S . -B DebugLinuxOpenSSL1 && \
  cmake --build DebugLinuxOpenSSL1 --parallel && \
  find . -type f -not -regex '.*Simulator\|.*\.gcno\|.*\.c\|.*\.h' -exec rm {} \; && \
  ln -s ./DebugLinuxOpenSSL1/Simulator/Simulator tpm2-simulator

# Symlink /tpm2-simulator to the openssl1 one, for convenience of users who just want "a" simulator.
RUN ln -s /simulators/openssl1/tpm2-simulator /tpm2-simulator

# ==============================================================================
# All code above this line is verbatim from the TPM Dockerfile, with the
# following exceptions:
#  - replace the COPY statement with RUN git clone to obtain the TPM sources.

WORKDIR /tpm-rs
ENV TPM_RS_SIMULATOR=/tpm2-simulator

# Install Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo --version
