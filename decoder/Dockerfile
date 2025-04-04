# Base image for your build environment (ubuntu)
FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Example Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
# Installing necessary build tools and wolfssl-dev (for headers)
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
    libwolfssl-dev  # This installs the wolfSSL library and headers

# Install MSDK
RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02
# Add the real-time library linker option
ENV LDFLAGS=-lrt

# Add your application source code (assuming this is already present in ./decoder/)
WORKDIR /decoder

# If necessary, you can explicitly set the include path for wolfSSL in the Dockerfile
# Set the CFLAGS environment variable to include the wolfssl header directory
ENV CFLAGS="-I/usr/include/wolfssl"

# Optionally, you can also set the library path if the linking is an issue
ENV LIBRARY_PATH="/usr/lib/x86_64-linux-gnu:$LIBRARY_PATH"

# Run the build process (Assuming 'make' is the standard command in the Makefile)
CMD ["make"]

ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef your-image-name
