cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

configure_file(enftun-cmd@.service.in enftun-cmd@.service @ONLY)
configure_file(enftun-data@.service.in enftun-data@.service @ONLY)

set(INSTALL_SYSTEMDDIR "/lib/systemd/system")

install(
  FILES
  ${CMAKE_CURRENT_BINARY_DIR}/enftun-cmd@.service
  ${CMAKE_CURRENT_BINARY_DIR}/enftun-data@.service
  DESTINATION
  ${INSTALL_SYSTEMDDIR}
)
