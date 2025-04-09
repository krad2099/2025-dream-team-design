#----------------------------------------------------------------
# Generated CMake target import file for configuration "MinSizeRel".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "wolfssl::wolfssl" for configuration "MinSizeRel"
set_property(TARGET wolfssl::wolfssl APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(wolfssl::wolfssl PROPERTIES
  IMPORTED_IMPLIB_MINSIZEREL "${_IMPORT_PREFIX}/lib/wolfssl.lib"
  IMPORTED_LOCATION_MINSIZEREL "${_IMPORT_PREFIX}/bin/wolfssl.dll"
  )

list(APPEND _cmake_import_check_targets wolfssl::wolfssl )
list(APPEND _cmake_import_check_files_for_wolfssl::wolfssl "${_IMPORT_PREFIX}/lib/wolfssl.lib" "${_IMPORT_PREFIX}/bin/wolfssl.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
