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

project(retest)


##############################################################################
#
# Module/Package Includes
#

find_package(OpenSSL)


##############################################################################
#
# Compile options
#

option(USE_OPENSSL "Enable OpenSSL" ${OPENSSL_FOUND})

include_directories(
  src
  ../re/include
  ../rem/include
  /usr/local/include
  /usr/local/include/re
  /usr/local/include/rem
)

link_directories(/usr/local/lib)

add_definitions(
  -DHAVE_GETOPT
  -DHAVE_INET6
  -DHAVE_PTHREAD
  -DHAVE_SIGNAL
  -DHAVE_UNISTD_H
  -DUSE_ZLIB
  )

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
# Source section
#

set (SRCS
  src/aac.c
  src/aes.c
  src/aubuf.c
  src/aulevel.c
  src/auresamp.c
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

add_executable(${PROJECT_NAME}
  ${SRCS}
)
target_link_libraries(${PROJECT_NAME} rem re -lz -lpthread -lm)
