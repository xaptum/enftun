include(LibFindMacros)

# Use pkg-config to get hints about paths
libfind_pkg_check_modules(slirp_PKGCONF slirp)
libfind_pkg_check_modules(vdeslirp_PKGCONF vdeslirp)

###############################################################################
# Find the include dirs
###############################################################################
find_path(slirp_INCLUDE_DIR
  NAMES slirp/libslirp.h
  PATHS ${slirp_PKGCONF_INCLUDE_DIRS}
  )

find_path(vdeslirp_INCLUDE_DIR
  NAMES slirp/libvdeslirp.h
  PATHS ${vdeslirp_PKGCONF_INCLUDE_DIRS}
  )

###############################################################################
# threads Library
###############################################################################
find_package(Threads REQUIRED)

###############################################################################
# glib 2 Library
###############################################################################
find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

###############################################################################
# libslirp Library
###############################################################################
find_library(slirp_LIBRARY
  NAMES slirp
  PATHS ${slirp_PKGCONFIG_LIBRARY_DIRS}
  )

set(slirp_PROCESS_INCLUDES slirp_INCLUDE_DIR)
set(slirp_PROCESS_LIBS slirp_LIBRARY)

libfind_process(slirp)

if (slirp_FOUND)
  if (NOT TARGET vdeslirp::slirp)

    add_library(vdeslirp::slirp UNKNOWN IMPORTED)

    set_target_properties(vdeslirp::slirp PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${slirp_INCLUDE_DIR}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${slirp_LIBRARY}"
    )

  endif ()
endif ()

###############################################################################
# libvdeslirp Library
###############################################################################
find_library(vdeslirp_LIBRARY
  NAMES vdeslirp
  PATHS ${vdeslirp_PKGCONFIG_LIBRARY_DIRS}
  )

set(vdeslirp_PROCESS_INCLUDES vdeslirp_INCLUDE_DIR)
set(vdeslirp_PROCESS_LIBS vdeslirp_LIBRARY)

libfind_process(vdeslirp)

if (vdeslirp_FOUND)
  if (NOT TARGET vdeslirp::vdeslirp)

    add_library(vdeslirp::vdeslirp UNKNOWN IMPORTED)

    set_target_properties(vdeslirp::vdeslirp PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${vdeslirp_INCLUDE_DIR};${slirp_INCLUDE_DIR};${GLIB_INCLUDE_DIRS}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${vdeslirp_LIBRARY}"
      INTERFACE_LINK_LIBRARIES "vdeslirp::slirp;Threads::Threads;${GLIB_LDFLAGS}"
    )

  endif ()
endif ()
