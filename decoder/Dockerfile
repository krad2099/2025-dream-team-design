# syntax=docker/dockerfile:1.4
# Dockerfile for the 2025 eCTF with MD5-based integration (using libcrypto for MD5)

FROM ubuntu:24.04

LABEL version="0.3"
LABEL description="Dream Team Decoder Docker Container for the 2025 eCTF with MD5 Integration"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install required packages (ARM-specific packages removed)
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
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
    cmake \
    libc6-dev

# Install MSDK (Maxim SDK)
RUN wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

# Set environment variable for Maxim SDK
ENV MAXIM_PATH=/root/msdk-2024_02

# Optionally, set paths for system and SDK headers/libraries if needed
ENV C_INCLUDE_PATH="/usr/include:/root/msdk-2024_02/Libraries/PeriphDrivers/Include"
ENV LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:/root/msdk-2024_02/Libraries/PeriphDrivers/Lib"

# Install Python dependencies (pycryptodome for your Python MD5 code)
RUN pip3 install pycryptodome

# Copy source files and header files into the container
COPY ./src /src
COPY ./inc /inc

WORKDIR /decoder

# Compile the C source files; MD5 functions are in libcrypto.
# We use "-I/inc" to find your headers and link with libcrypto (-lcrypto).
RUN gcc -o /root/dream_team_decoder /src/simple_crypto.c /src/decoder.c /src/host_messaging.c /src/simple_flash.c /src/simple_uart.c -I/inc -lcrypto

# Set the entry point for building the decoder firmware
ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run --rm -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder
