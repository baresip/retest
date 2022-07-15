#
# CMakeLists.txt
#
# Copyright (C) 2010 - 2022 Alfred E. Heggestad
#

##############################################################################
#
# Versioning
#

cmake_minimum_required(VERSION 3.7)

project(retest C)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)


##############################################################################
#
# Module/Package Includes
#

include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckSymbolExists)
find_package(RE REQUIRED)
find_package(REM REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL)


##############################################################################
#
# Compile options/definitions
#

option(USE_OPENSSL "Enable OpenSSL" ${OPENSSL_FOUND})

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)

if(MSVC)
  add_compile_options("/W3")
else()
  add_compile_options(
    -Wall
    -Wbad-function-cast
    -Wcast-align
    -Wextra
    -Wmissing-declarations
    -Wmissing-prototypes
    -Wnested-externs
    -Wold-style-definition
    -Wshadow -Waggregate-return
    -Wstrict-prototypes
    -Wvla
  )
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wshorten-64-to-32)
endif()

check_include_file(unistd.h HAVE_UNISTD_H)
if(HAVE_UNISTD_H)
  add_definitions(-DHAVE_UNISTD_H)
endif()

check_function_exists(thrd_create HAVE_THREADS)
if(HAVE_THREADS)
  add_definitions(-DHAVE_THREADS)
endif()

if(CMAKE_USE_PTHREADS_INIT)
  add_definitions(-DHAVE_PTHREAD)
  set(HAVE_PTHREAD ON)
endif()

check_symbol_exists("arc4random" "stdlib.h" HAVE_ARC4RANDOM)
if(HAVE_ARC4RANDOM)
  add_definitions(-DHAVE_ARC4RANDOM)
endif()


include_directories(
  src
  ../re/include
  ../rem/include
  ${RE_INCLUDE_DIRS}
  ${REM_INCLUDE_DIRS}
)

add_definitions(
  -DHAVE_ATOMIC
  -DHAVE_INET6
  -DHAVE_SELECT
  )

if(UNIX)
  add_definitions(
    -DHAVE_GETOPT
    -DHAVE_POLL
    -DHAVE_PWD_H
    -DHAVE_ROUTE_LIST
    -DHAVE_SETRLIMIT
    -DHAVE_STRERROR_R
    -DHAVE_STRINGS_H
    -DHAVE_SYS_TIME_H
    -DHAVE_UNAME
    -DHAVE_SELECT_H
    -DHAVE_SIGNAL
    )
  if(NOT ANDROID)
    add_definitions(-DHAVE_GETIFADDRS)
  endif()
endif()


if(MSVC)
  add_definitions(
    -DHAVE_IO_H
    -D_CRT_SECURE_NO_WARNINGS
  )
endif()

if(WIN32)
  add_definitions(
    -DWIN32 -D_WIN32_WINNT=0x0600
  )
endif()

if(USE_OPENSSL)
  add_definitions(
    -DUSE_DTLS
    -DUSE_OPENSSL
    -DUSE_OPENSSL_AES
    -DUSE_OPENSSL_DTLS
    -DUSE_OPENSSL_HMAC
    -DUSE_OPENSSL_SRTP
    -DUSE_TLS
  )
endif()


##############################################################################
#
# Source/Header section
#

set(SRCS
  src/aac.c
  src/aes.c
  src/aubuf.c
  src/aulevel.c
  src/auresamp.c
  src/av1.c
  src/base64.c
  src/bfcp.c
  src/conf.c
  src/convert.c
  src/crc32.c
  src/dns.c
  src/dsp.c
  src/dtmf.c
  src/fir.c
  src/fmt.c
  src/g711.c
  src/h264.c
  src/h265.c
  src/hash.c
  src/hmac.c
  src/http.c
  src/httpauth.c
  src/ice.c
  src/jbuf.c
  src/json.c
  src/list.c
  src/main.c
  src/mbuf.c
  src/md5.c
  src/mem.c
  src/mock/dnssrv.c
  src/mock/fuzz.c
  src/mock/nat.c
  src/mock/pf.c
  src/mock/sipsrv.c
  src/mock/stunsrv.c
  src/mock/tcpsrv.c
  src/mock/turnsrv.c
  src/mqueue.c
  src/net.c
  src/odict.c
  src/pcp.c
  src/remain.c
  src/rtcp.c
  src/rtmp.c
  src/rtp.c
  src/sa.c
  src/sdp.c
  src/sha.c
  src/sip.c
  src/sipauth.c
  src/sipevent.c
  src/sipreg.c
  src/sipsess.c
  src/srtp.c
  src/stun.c
  src/sys.c
  src/tcp.c
  src/telev.c
  src/test.c
  src/thread.c
  src/tmr.c
  src/trace.c
  src/trice.c
  src/turn.c
  src/udp.c
  src/uri.c
  src/vid.c
  src/vidconv.c
  src/websock.c
)

if(USE_OPENSSL)
  list(APPEND SRCS
    src/tls.c
    src/dtls.c
    src/combo/dtls_turn.c
    src/mock/cert.c
  )
endif()


##############################################################################
#
# Main target object
#

add_executable(${PROJECT_NAME} ${SRCS})
set_property(TARGET ${PROJECT_NAME} PROPERTY ENABLE_EXPORTS 1)

target_link_libraries(${PROJECT_NAME}
    PRIVATE ${REM_LIBRARIES} ${RE_LIBRARIES} ${OPENSSL_LIBRARIES}
    -lz -lpthread -lm)
target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
