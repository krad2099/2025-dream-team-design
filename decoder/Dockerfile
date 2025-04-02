# syntax=docker/dockerfile:1
FROM docker
COPY --from=docker/buildx-bin /buildx /usr/libexec/docker/cli-plugins/docker-buildx
RUN docker buildx version

# Dockerfile for the 2025 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Example Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
# do this first because it takes the longest
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3.10 \
    git \
    wget \
    libtool \
    texinfo \
    unzip    

# Install MSDK
RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

# Build and configure WolfSSL
WORKDIR /root
RUN wget https://www.wolfssl.com/download/wolfssl-5.7.6.tar.gz && \
    tar -xzf wolfssl-5.7.6.tar.gz && \
    cd wolfssl-5.7.6 && \
    # WolfSSL expects version.h.in to be in wolfssl/; create that directory and copy it if needed
    mkdir -p wolfssl && cp version.h.in wolfssl/version.h.in && \
    ./configure --enable-harden && \
    make && \
    # Create a lib directory in your MSDK inc folder (adjust path as needed)
    mkdir -p /root/msdk-2024_02/inc/wolfssl/lib && \
    # Copy the entire configured wolfssl directory into your project's include folder
    cp -R wolfssl /root/msdk-2024_02/inc/ && \
    # Copy the built static library so that your linker can find it
    cp libwolfssl.a /root/msdk-2024_02/inc/wolfssl/lib/

ENV MAXIM_PATH=/root/msdk-2024_02
# Add the real-time library linker option
ENV LDFLAGS=-lrt

WORKDIR /decoder

ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder

