# Pulls a reference TPM simulator to run tests against.
FROM ubuntu:latest
ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /tpm-rs

# Install simulator dependencies
RUN apt-get update && apt-get install -y git curl wget autoconf-archive pkg-config build-essential automake trousers libtspi-dev
# TODO: Replace with more recent openssl when https://github.com/microsoft/ms-tpm-20-ref/issues/90 is fixed.
RUN wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz && tar xzvf openssl-1.1.1w.tar.gz
RUN cd openssl-1.1.1w && ./config && make && make install
RUN ldconfig

# Build and copy the simulator
RUN git clone https://github.com/microsoft/ms-tpm-20-ref.git
RUN cd ms-tpm-20-ref/TPMCmd && ./bootstrap && ./configure && make \
&& cp ./Simulator/src/tpm2-simulator /
ENV TPM_RS_SIMULATOR=/tpm2-simulator

# Install Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo --version