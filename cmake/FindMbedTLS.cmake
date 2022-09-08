# lint_cmake: -convention/filename
# lint_cmake: -package/stdargs
# lint_cmake: -whitespace/indent
find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h HINTS ${MBEDTLS_DIR}/include)

find_library(MBEDTLS_LIBRARY mbedtls HINTS ${MBEDTLS_DIR}/lib)
find_library(MBEDX509_LIBRARY mbedx509 HINTS ${MBEDTLS_DIR}/lib)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto HINTS ${MBEDTLS_DIR}/lib)

set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}"
                      "${MBEDCRYPTO_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  MbedTLS DEFAULT_MSG MBEDTLS_LIBRARY MBEDTLS_INCLUDE_DIRS MBEDX509_LIBRARY
  MBEDCRYPTO_LIBRARY)

mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY
                 MBEDCRYPTO_LIBRARY)

if(NOT TARGET MbedTLS)
  message("in mbedtls ${MBEDTLS_LIBRARY}")
  add_library(MbedTLS UNKNOWN IMPORTED)
  set_target_properties(
    MbedTLS
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIRS}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${MBEDTLS_LIBRARY}")
endif()

if(NOT TARGET MbedCrypto)
  add_library(MbedCrypto UNKNOWN IMPORTED)
  set_target_properties(
    MbedCrypto
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIRS}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${MBEDCRYPTO_LIBRARY}")
endif()

if(NOT TARGET MbedX509)
  add_library(MbedX509 UNKNOWN IMPORTED)
  set_target_properties(
    MbedX509
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIRS}"
               IMPORTED_LINK_INTERFACE_LANGUAGES "C"
               IMPORTED_LOCATION "${MBEDX509_LIBRARY}")
endif()
