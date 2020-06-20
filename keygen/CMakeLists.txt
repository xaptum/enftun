cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

project(enftun-keygen
  VERSION 0.0.1
  LANGUAGES C
)

include(GNUInstallDirs)

find_package(OpenSSL REQUIRED QUIET 1.1)
find_package(Jansson REQUIRED)
find_package(CURL REQUIRED)
find_package(sodium REQUIRED QUIET 1.0.11)

add_compile_options(-std=c99 -Wall -Wextra -Wno-missing-field-initializers)

add_executable(enftun-keygen
    src/main.c
    src/json_tools.c
    src/auth.c
    src/ssl.c
    src/curl.c
    src/iam.c
    src/enftun/config.c
    src/enftun/log.c
    )

target_include_directories(enftun-keygen
    PRIVATE
    ${CURL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
    )

target_link_libraries(enftun-keygen
    PUBLIC ${CURL_LIBRARIES}
    ${OPENSSL_SSL_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARIES}
    ${JANSSON_LIBRARIES}
    LibConfig::LibConfig
    sodium
    )
set_target_properties(enftun-keygen
  PROPERTIES
  C_STANDARD 99
)

if (MSVC)
  target_compile_options(enftun-keygen PRIVATE /W4 /WX)
else(MSVC)
  target_compile_options(enftun-keygen PRIVATE -Wall -Wextra)
endif(MSVC)

install(
    TARGETS enftun-keygen
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    )