cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(enftun
  VERSION 0.9.1
  LANGUAGES C
)

option(BUILD_CACERT  "Install the the ENF ca cert" ON)
option(BUILD_EXAMPLE "Build and install example configs" ON)
option(BUILD_HSS   "Build with hss support" OFF)
option(BUILD_SYSTEMD "Build with systemd support" ON)
option(BUILD_TEST    "Build tests" ON)
option(BUILD_XTT     "Build with XTT support" ON)
option(BUILD_KEYGEN  "Build with keygen tool" ON)
option(BUILD_SLIRP   "Build with libslirp backend" OFF)
option(BUILD_TPM     "Build with TPM support" ON)
option(CHECK_FORMAT  "Check source format during build" ON)

include(GNUInstallDirs)

find_package(LibConfig REQUIRED QUIET 1.5)
find_package(LibUV REQUIRED QUIET 1.9)
find_package(OpenSSL REQUIRED QUIET 1.0)

if(BUILD_XTT)
    set(BUILD_TPM ON CACHE BOOL "Build with TPM support" FORCE)
    add_definitions(-DUSE_XTT)
    find_package(sodium REQUIRED QUIET 1.0.11)
    find_package(TSS2 REQUIRED QUIET)
    find_package(xtt COMPONENTS tpm REQUIRED QUIET 0.12.0)
endif()

if(BUILD_TPM)
    add_definitions(-DUSE_TPM)
    find_package(TSS2 REQUIRED QUIET)
endif()

if(BUILD_HSS)
    add_definitions(-DUSE_HSS)
endif()

if(BUILD_SLIRP)
    add_definitions(-DUSE_SLIRP)
    find_package(vdeslirp REQUIRED)
endif()

add_compile_options(-std=c99 -Wall -Wextra -Wno-missing-field-initializers -Wno-missing-braces)
set(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -Werror -D_FORTIFY_SOURCE=2 -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")
set(CMAKE_C_FLAGS_DEV "${CMAKE_C_FLAGS_RELEASE} -O2 -Werror -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS_DEVDEBUG "${CMAKE_C_FLAGS_DEBUG} -O2 -Werror -D_FORTIFY_SOURCE=2")

add_custom_target(check-format
                  COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/format.sh check || (exit 0)
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

set(ENFTUN_SRCS
    src/cert.c
    src/chain.c
    src/channel.c
    src/cksum.c
    src/config.c
    src/conn_state.c
    src/context.c
    src/dhcp.c
    src/dhcp6_msgs.c
    src/enftun.c
    src/exec.c
    src/filter.c
    src/heartbeat.c
    src/icmp6.c
    src/ip6.c
    src/log.c
    src/ndp.c
    src/netlink.c
    src/options.c
    src/packet.c
    src/pcap.c
    src/sockaddr.c
    src/tcp.c
    src/tcp_multi.c
    src/tls.c
    src/tls_tpm.c
    src/tun.c
    src/udp.c
    )

if(BUILD_XTT)
    list(APPEND ENFTUN_SRCS src/xtt.c)
endif()

if(BUILD_HSS)
    list(APPEND ENFTUN_SRCS src/tcp_hss.c)
endif()

if(BUILD_SLIRP)
    list(APPEND ENFTUN_SRCS src/slirp.c)
endif()

configure_file(src/version.h.in version.h)

add_executable(enftun ${ENFTUN_SRCS})

target_include_directories(enftun PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)

target_link_libraries(enftun
  PRIVATE
  LibConfig::LibConfig
  LibUV::LibUV
  m
  OpenSSL::SSL
)

if(BUILD_XTT)
    target_link_libraries(enftun
    PRIVATE
    xtt::xtt
    sodium)
endif()

if(BUILD_SLIRP)
    target_link_libraries(enftun
    PRIVATE
    vdeslirp::vdeslirp)
endif()

set_target_properties(enftun
  PROPERTIES
  C_STANDARD 99
)

if (MSVC)
  target_compile_options(enftun PRIVATE /W4 /WX)
else(MSVC)
  target_compile_options(enftun PRIVATE -Wall -Wextra)
endif(MSVC)

install(
  TARGETS enftun
  DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_subdirectory(tools)

if (BUILD_CACERT)
  install(
    FILES enf.cacert.pem
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/enftun
  )
endif()

if (BUILD_EXAMPLE)
  add_subdirectory(example)
endif()

if (BUILD_SYSTEMD)
  add_subdirectory(systemd)
endif()

if (BUILD_TEST)
  add_subdirectory(test)
endif()

if (BUILD_KEYGEN)
  add_subdirectory(keygen)
endif()

if (CHECK_FORMAT)
  add_dependencies(enftun check-format)
endif()
