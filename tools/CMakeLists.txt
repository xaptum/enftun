cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

configure_file(enftun-setup ${CMAKE_CURRENT_BINARY_DIR}/enftun-setup COPYONLY)
configure_file(wait_for_iface ${CMAKE_CURRENT_BINARY_DIR}/wait_for_iface COPYONLY)
configure_file(wait_for_iface_up ${CMAKE_CURRENT_BINARY_DIR}/wait_for_iface_up COPYONLY)

install(
  PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/enftun-setup ${CMAKE_CURRENT_BINARY_DIR}/wait_for_iface ${CMAKE_CURRENT_BINARY_DIR}/wait_for_iface_up
  DESTINATION ${CMAKE_INSTALL_BINDIR}
)
