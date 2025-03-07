# Dockerfile for the 2025 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Dream Team Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

ENV DOCKER_BUILDKIT=1

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
    unzip \
    build-essential \
    libssl-dev \
    pkg-config \
    libc6-dev
    



# Install MSDK
RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

# Set environment variables for Maxim SDK
ENV MAXIM_PATH=/root/msdk-2024_02

# Set OpenSSL path for libraries and includes
ENV LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:$LIBRARY_PATH"
ENV C_INCLUDE_PATH="/usr/include:/root/msdk-2024_02/Libraries/PeriphDrivers/Include:$C_INCLUDE_PATH"
COPY ./src /src

COPY ./inc /inc


WORKDIR /decoder

ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder

