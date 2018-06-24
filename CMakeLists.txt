cmake_minimum_required(VERSION 3.0)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(enftun
  VERSION 0.1.0
  LANGUAGES C
  )

find_package(LibConfig REQUIRED QUIET 1.5)
find_package(LibUV REQUIRED QUIET 1.9)
find_package(OpenSSL REQUIRED QUIET 1.1)

add_executable(enftun
  src/cert.c
  src/chain.c
  src/channel.c
  src/enftun.c
  src/filter.c
  src/log.c
  src/options.c
  src/packet.c
  src/tls.c
  src/tun.c
)

target_link_libraries(enftun
  PRIVATE LibConfig::LibConfig
          LibUV::LibUV
          OpenSSL::SSL
)

configure_file(example/example.conf    conf/example.conf    COPYONLY)
configure_file(example/example.crt.pem conf/example.crt.pem COPYONLY)
configure_file(example/example.key.pem conf/example.key.pem COPYONLY)
configure_file(test/router.crt.pem     conf/router.crt.pem  COPYONLY)
