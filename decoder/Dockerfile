FROM ubuntu:24.04

LABEL version="0.3"
LABEL description="Decoder Docker Container with custom WolfSSL headers"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install build tools (no libwolfssl-dev!)
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
RUN wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02
ENV LDFLAGS=-lrt

# Copy your decoder source code and custom wolfssl headers
COPY . /decoder
COPY ../inc/wolfssl /usr/local/include/wolfssl

WORKDIR /decoder

# Point to the custom wolfssl path
ENV CFLAGS="-I/usr/local/include"

# If needed, tell linker where to find custom libs (if any)
ENV LIBRARY_PATH="/usr/local/lib:$LIBRARY_PATH"

# Default make command
CMD ["make"]

# Bot entrypoint — using env var DECODER_ID
ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]
