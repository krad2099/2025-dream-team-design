FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Example Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3 \
    python3-pip \
    python3-cryptography \
    git \
    wget \
    libtool \
    texinfo \
    unzip \
    libssl-dev \
    openssl \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Install MSDK
RUN wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02

# Install WolfSSL (with cryptography support)
RUN git clone --depth=1 https://github.com/wolfSSL/wolfssl.git && \
    cd wolfssl && \
    ./autogen.sh && \
    ./configure --enable-cryptonly && \
    make -j$(nproc) && \
    make install && \
    ldconfig

WORKDIR /decoder

# Set entrypoint to allow flexible commands during container execution
ENTRYPOINT ["bash", "-c"]

# Default command for building the decoder
CMD ["make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]
