# Dockerfile for the 2025 eCTF with OpenSSL integration

FROM ubuntu:24.04

LABEL version="0.3"
LABEL description="Example Decoder Docker Container for the 2025 eCTF with OpenSSL Integration"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /decoder

# Install Requisite Packages
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3.10 \
    python3-pip \
    git \
    wget \
    libtool \
    texinfo \
    unzip \
    build-essential \
    libssl-dev \
    pkg-config \
    wget \
    cmake \

# Install MSDK (Maxim SDK)
RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

# Set OpenSSL installation
ENV OPENSSL_PATH=/usr/include/openssl
ENV LIBRARY_PATH="$LIBRARY_PATH:/usr/lib/x86_64-linux-gnu"
ENV C_INCLUDE_PATH="$C_INCLUDE_PATH:/usr/include/openssl"

# Install Python dependencies
RUN pip3 install pyOpenSSL


# Copy the crypto library (which includes crypto.h and crypto.c) into the container
COPY ./crypto /root/crypto

# Set environment variables for Maxim path
ENV MAXIM_PATH=/root/msdk-2024_02

WORKDIR /decoder

# Entry point for building the decoder firmware with wolfSSL integration
ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command for building the decoder
# docker run --rm -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder
