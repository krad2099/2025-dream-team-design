# syntax=docker/dockerfile:1.4
# Dockerfile for the 2025 eCTF
FROM ubuntu:24.04

LABEL version="0.3"
LABEL description="Dream Team Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

ENV DOCKER_BUILDKIT=1

# Install Requisite Packages
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3 \
    python3-pip \
    git \
    wget \
    libtool \
    texinfo \
    unzip \
    build-essential \
    libwolfssl-dev \
    pkg-config \
    libc6-dev \
    glibc-source \
    gcc \
    g++ \
    libstdc++-12-dev \
    --no-install-recommends
    

# Install MSDK
RUN wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

# Set environment variables for Maxim SDK
ENV MAXIM_PATH=/root/msdk-2024_02

# Set paths for system and SDK headers/libraries
ENV C_INCLUDE_PATH="/usr/include:/root/msdk-2024_02/Libraries/PeriphDrivers/Include"
ENV LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:/root/msdk-2024_02/Libraries/PeriphDrivers/Lib"

# Ensure GCC is in PATH
ENV PATH="$PATH:/root/msdk-2024_02/toolchains/arm-none-eabi/bin"

# Copy source files
COPY ./src /src
COPY ./inc /inc

WORKDIR /decoder


      
ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder

