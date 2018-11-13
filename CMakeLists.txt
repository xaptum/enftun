cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(enftun
  VERSION 0.1.4
  LANGUAGES C
)

option(BUILD_CACERT  "Install the the ENF ca cert" ON)
option(BUILD_EXAMPLE "Build and install example configs" ON)
option(BUILD_SYSTEMD "Build with systemd support" ON)
option(BUILD_TEST "Build tests" ON)

include(GNUInstallDirs)

find_package(LibConfig REQUIRED QUIET 1.5)
find_package(LibUV REQUIRED QUIET 1.9)
find_package(OpenSSL REQUIRED QUIET 1.1)

add_executable(enftun
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
  src/tls.c
  src/tun.c
)

target_link_libraries(enftun
  PRIVATE
  LibConfig::LibConfig
  LibUV::LibUV
  OpenSSL::SSL
)

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
