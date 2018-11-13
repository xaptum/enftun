cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

set(INSTALL_EXAMPLEDIR "${CMAKE_INSTALL_DOCDIR}/example")

install(
  FILES
  device.conf
  server.conf
  DESTINATION
  ${INSTALL_EXAMPLEDIR}
)
