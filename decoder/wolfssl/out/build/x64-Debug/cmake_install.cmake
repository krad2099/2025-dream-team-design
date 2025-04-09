# Install script for directory: H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/install/x64-Debug")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY OPTIONAL FILES "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/wolfssl.lib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE SHARED_LIBRARY FILES "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/wolfssl.dll")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wolfssl" TYPE DIRECTORY FILES "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/wolfssl/" FILES_MATCHING REGEX "/[^/]*\\.h$" REGEX "(internal.h|wolfssl/wolfcrypt/port/nrf51.h|wolfssl/wolfcrypt/port/arm|wolfssl/wolfcrypt/port/cypress|wolfssl/wolfcrypt/port/espressif|wolfssl/wolfcrypt/port/iotsafe|wolfssl/wolfcrypt/port/nxp|wolfssl/wolfcrypt/port/pic|wolfssl/wolfcrypt/port/renesas|wolfssl/wolfcrypt/port/silabs|wolfssl/wolfcrypt/port/st|wolfssl/wolfcrypt/port/ti|wolfssl/wolfcrypt/port/xilinx|wolfssl/wolfcrypt/port/atmel|wolfssl/wolfcrypt/port/af_alg|wolfssl/wolfcrypt/port/kcapi|wolfssl/wolfcrypt/port/devcrypto|wolfssl/wolfcrypt/async.h|wolfssl/wolfcrypt/wc_pkcs11.h|wolfssl/wolfcrypt/pkcs11.h|wolfssl/wolfcrypt/port/cavium|wolfssl/wolfcrypt/port/intel|wolfssl/wolfcrypt/sp.h|wolfssl/wolfcrypt/selftest.h|wolfssl/wolfcrypt/fips.h|wolfssl/wolfcrypt/port/caam)" EXCLUDE)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/wolfssl" TYPE DIRECTORY FILES "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/wolfssl/" FILES_MATCHING REGEX "/[^/]*\\.h$" REGEX "(internal.h|wolfssl/wolfcrypt/port/nrf51.h|wolfssl/wolfcrypt/port/arm|wolfssl/wolfcrypt/port/cypress|wolfssl/wolfcrypt/port/espressif|wolfssl/wolfcrypt/port/iotsafe|wolfssl/wolfcrypt/port/nxp|wolfssl/wolfcrypt/port/pic|wolfssl/wolfcrypt/port/renesas|wolfssl/wolfcrypt/port/silabs|wolfssl/wolfcrypt/port/st|wolfssl/wolfcrypt/port/ti|wolfssl/wolfcrypt/port/xilinx|wolfssl/wolfcrypt/port/atmel|wolfssl/wolfcrypt/port/af_alg|wolfssl/wolfcrypt/port/kcapi|wolfssl/wolfcrypt/port/devcrypto|wolfssl/wolfcrypt/async.h|wolfssl/wolfcrypt/wc_pkcs11.h|wolfssl/wolfcrypt/pkcs11.h|wolfssl/wolfcrypt/port/cavium|wolfssl/wolfcrypt/port/intel|wolfssl/wolfcrypt/sp.h|wolfssl/wolfcrypt/selftest.h|wolfssl/wolfcrypt/fips.h|wolfssl/wolfcrypt/port/caam)" EXCLUDE)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/wolfssl/example" TYPE FILE FILES
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/examples/echoserver/echoserver.c"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/examples/sctp/sctp-server.c"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/examples/sctp/sctp-client-dtls.c"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/examples/sctp/sctp-client.c"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/examples/sctp/sctp-server-dtls.c"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/examples/echoclient/echoclient.c"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/examples/server/server.c"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/examples/benchmark/tls_bench.c"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/examples/client/client.c"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/doc/wolfssl" TYPE FILE FILES
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/doc/README.txt"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/certs/taoCert.txt"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl/wolfssl-targets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl/wolfssl-targets.cmake"
         "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/CMakeFiles/Export/41263289dc9ec8a87d5b2cd96b0484fa/wolfssl-targets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl/wolfssl-targets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl/wolfssl-targets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl" TYPE FILE FILES "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/CMakeFiles/Export/41263289dc9ec8a87d5b2cd96b0484fa/wolfssl-targets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl" TYPE FILE FILES "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/CMakeFiles/Export/41263289dc9ec8a87d5b2cd96b0484fa/wolfssl-targets-debug.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/support/wolfssl.pc")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/wolfssl" TYPE FILE FILES
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/wolfssl-config.cmake"
    "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/wolfssl-config-version.cmake"
    )
endif()

if(CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_COMPONENT MATCHES "^[a-zA-Z0-9_.+-]+$")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
  else()
    string(MD5 CMAKE_INST_COMP_HASH "${CMAKE_INSTALL_COMPONENT}")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INST_COMP_HASH}.txt")
    unset(CMAKE_INST_COMP_HASH)
  endif()
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
  file(WRITE "H:/Users/Aalle/Desktop/ectf/main/2025-dream-team-design/decoder/inc/wolfssl-5.7.6/out/build/x64-Debug/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
