#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "wolfssl::wolfssl" for configuration "Release"
set_property(TARGET wolfssl::wolfssl APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(wolfssl::wolfssl PROPERTIES
  IMPORTED_IMPLIB_RELEASE "${_IMPORT_PREFIX}/lib/wolfssl.lib"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/bin/wolfssl.dll"
  )

list(APPEND _cmake_import_check_targets wolfssl::wolfssl )
list(APPEND _cmake_import_check_files_for_wolfssl::wolfssl "${_IMPORT_PREFIX}/lib/wolfssl.lib" "${_IMPORT_PREFIX}/bin/wolfssl.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
