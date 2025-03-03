# Dockerfile for the 2025 eCTF
# Updated to ensure Python virtual environment is always activated

FROM ubuntu:24.04

LABEL version="0.3"
LABEL description="Secure Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages (Updated)
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3.10 \
    python3-pip \
    python3-venv \
    git \
    wget \
    cmake \
    clang \
    ninja-build \
    libtool \
    texinfo \
    unzip \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install MSDK
RUN wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02

# Install Python Virtual Environment with Secure Dependencies
WORKDIR /decoder
RUN python3 -m venv venv && \
    . venv/bin/activate && \
    pip install --upgrade pip && \
    pip install cryptography loguru

# Ensure the virtual environment is activated inside the container
ENV VIRTUAL_ENV=/decoder/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install wolfSSL for C-based AES-GCM and HMAC
RUN git clone --depth 1 --branch v5.6.0-stable https://github.com/wolfSSL/wolfssl.git && \
    cd wolfssl && \
    ./autogen.sh && \
    ./configure --enable-aesgcm --enable-hmac && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf wolfssl

# Set environment variables for wolfSSL
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV LD_LIBRARY_PATH=/usr/local/lib

# Ensure the decoder builds successfully
ENTRYPOINT ["bash", "-c", "source /decoder/venv/bin/activate && make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder