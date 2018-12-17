cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(enftun
  VERSION 0.2.1
  LANGUAGES C
)

option(BUILD_CACERT  "Install the the ENF ca cert" ON)
option(BUILD_EXAMPLE "Build and install example configs" ON)
option(BUILD_SYSTEMD "Build with systemd support" ON)
option(BUILD_TEST    "Build tests" ON)
option(BUILD_XTT     "Build with XTT support" ON)

include(GNUInstallDirs)

find_package(LibConfig REQUIRED QUIET 1.5)
find_package(LibUV REQUIRED QUIET 1.9)
find_package(OpenSSL REQUIRED QUIET 1.1)

if(BUILD_XTT)
    add_definitions(-DUSE_TPM)
    add_definitions(-DUSE_XTT)
    find_package(sodium REQUIRED QUIET 1.0.11)
    find_package(xtt COMPONENTS tpm REQUIRED QUIET 0.10.1)
endif()

add_compile_options(-std=c99 -Wall -Wextra -Wno-missing-field-initializers)
set(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")
set(CMAKE_C_FLAGS_DEV "${CMAKE_C_FLAGS_RELEASE} -Werror")
set(CMAKE_C_FLAGS_DEVDEBUG "${CMAKE_C_FLAGS_DEBUG} -Werror")

set(ENFTUN_SRCS
    src/cert.c
    src/chain.c
    src/channel.c
    src/config.c
    src/context.c
    src/enftun.c
    src/exec.c
    src/filter.c
    src/ip.c
    src/log.c
    src/options.c
    src/packet.c
    src/tcp.c
    src/tls.c
    src/tun.c
    )

if(BUILD_XTT)
    list(APPEND ENFTUN_SRCS src/xtt.c)
endif()

add_executable(enftun ${ENFTUN_SRCS})

target_link_libraries(enftun
  PRIVATE
  LibConfig::LibConfig
  LibUV::LibUV
  OpenSSL::SSL
)

if(BUILD_XTT)
    target_link_libraries(enftun
    PRIVATE
    xtt::xtt
    sodium)
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
