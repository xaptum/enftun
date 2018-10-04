cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

configure_file(enftun@.service.in enftun@.service @ONLY)
configure_file(tun@.service tun@.service COPYONLY)

set(INSTALL_SYSTEMDDIR "/lib/systemd/system")

install(
  FILES
  ${CMAKE_CURRENT_BINARY_DIR}/enftun@.service
  ${CMAKE_CURRENT_BINARY_DIR}/tun@.service
  DESTINATION
  ${INSTALL_SYSTEMDDIR}
  )
