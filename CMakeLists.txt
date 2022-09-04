#
# CMakeLists.txt
#
# Copyright (C) 2010 - 2022 Alfred E. Heggestad
#

##############################################################################
#
# Versioning
#

cmake_minimum_required(VERSION 3.10)

project(retest C)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)


##############################################################################
#
# Module/Package Includes
#

find_package(RE REQUIRED)
find_package(REM REQUIRED)

##############################################################################
#
# Compile options/definitions
#

option(USE_SANITIZER "Sanitizers like: address, thread, undefined, memory")
include(sanitizer)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_BUILD_TYPE Debug)

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

include_directories(
  src
  ${RE_INCLUDE_DIRS}
  ${REM_INCLUDE_DIRS}
)

find_package(re CONFIG REQUIRED HINTS ../re/cmake)

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
  src/async.c
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

set(LINKLIBS ${REM_LIBRARIES} ${RE_LIBRARIES} ${OPENSSL_LIBRARIES})
if(WIN32)
  list(APPEND LINKLIBS qwave iphlpapi wsock32 ws2_32)
else()
  list(APPEND LINKLIBS -lz -lpthread -lm)
endif()

add_executable(${PROJECT_NAME} ${SRCS})
set_property(TARGET ${PROJECT_NAME} PROPERTY ENABLE_EXPORTS 1)

target_link_libraries(${PROJECT_NAME} PRIVATE ${LINKLIBS})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${RE_DEFINITIONS})

if(USE_OPENSSL)
  target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()
