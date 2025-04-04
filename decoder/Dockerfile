FROM ubuntu:24.04

LABEL version="0.4"
LABEL description="Decoder Docker Container with custom WolfSSL headers from /inc"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install build tools (no wolfssl-dev)
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

# Copy decoder source and the custom headers
COPY ./decoder /decoder
COPY ./inc /usr/local/include

WORKDIR /decoder

# Point to where wolfssl/options.h now lives
ENV CFLAGS="-I/usr/local/include"

# Optional: linker path for libs if needed
ENV LIBRARY_PATH="/usr/local/lib:$LIBRARY_PATH"

# Default build command
CMD ["make"]

# Bot build entrypoint
ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]
