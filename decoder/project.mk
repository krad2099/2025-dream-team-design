# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
VPATH+=src/
IPATH+=/opt/wolfssl

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
# Uncomment the commented lines below and comment the disable
# lines to enable the eCTF Crypto Example.
# WolfSSL must be included in this directory as wolfssl/
# WolfSSL can be downloaded from: https://www.wolfssl.com/download/

# Disable Crypto Example
#CRYPTO_EXAMPLE=0

# Enable Crypto Example
CRYPTO_EXAMPLE=1

# WolfSSL Library Linking & configuration

# Include the WolfSSL headers
CFLAGS += -Iinc  

# Ensure the library path points to the correct directory
LIBPATH := ./inc/wolfssl/src/.libs  # Update this path to where your libwolfssl.a or libwolfssl.so is located

# Add the library search flag to LDFLAGS. This tells the linker where to look for the library.
LDFLAGS += -L./inc/wolfssl/src/.libs -Wl,--gc--sections -lwolfssl

# Link the WolfSSL library (Uncommented to avoid linker error)
#LIBS += -lwolfssl  

# ****************** Additional Configuration *******************
# Add any other specific configurations you need here.

