cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

configure_file(enftun-setup ${CMAKE_CURRENT_BINARY_DIR}/enftun-setup COPYONLY)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/enftun-setup
  DESTINATION ${CMAKE_INSTALL_BINDIR}
)
