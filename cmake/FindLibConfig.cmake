#[=======================================================================[.rst:
FindLibConfig
---------

Find libConfig includes and library.

Imported Targets
^^^^^^^^^^^^^^^^

An :ref:`imported target <Imported targets>` named
``LibConfig::LibConfig`` is provided if libconfig has been found.

Result Variables
^^^^^^^^^^^^^^^^

This module defines the following variables:

``LibConfig_FOUND``
  True if libconfig was found, false otherwise.
``LibConfig_INCLUDE_DIRS``
  Include directories needed to include libconfig headers.
``LibConfig_LIBRARIES``
  Libraries needed to link to libconfig.
``LibConfig_VERSION``
  The version of libconfig. found.
``LibConfig_VERSION_MAJOR``
  The major version of libconfig.
``LibConfig_VERSION_MINOR``
  The minor version of libconfig.
``LibConfig_VERSION_PATCH``
  The patch version of libconfig.

Cache Variables
^^^^^^^^^^^^^^^

This module uses the following cache variables:

``LibConfig_LIBRARY``
  The location of the libconfig library file.
``LibConfig_INCLUDE_DIR``
  The location of the libconfig include directory containing ``libconfig.h``.

The cache variables should not be used by project code.
They may be set by end users to point at libconfig components.
#]=======================================================================]

#=============================================================================
# Copyright 2018 Xaptum, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-----------------------------------------------------------------------------
find_library(LibConfig_LIBRARY
  NAMES config
  )
mark_as_advanced(LibConfig_LIBRARY)

find_path(LibConfig_INCLUDE_DIR
  NAMES libconfig.h
  )
mark_as_advanced(LibConfig_INCLUDE_DIR)

#-----------------------------------------------------------------------------
# Extract version number if possible.
set(_LibConfig_H_REGEX "#[ \t]*define[ \t]+LIBCONFIG_VER_(MAJOR|MINOR|REVISION)[ \t]+[0-9]+")
if(LibConfig_INCLUDE_DIR AND EXISTS "${LibConfig_INCLUDE_DIR}/libconfig.h")
  file(STRINGS "${LibConfig_INCLUDE_DIR}/libconfig.h" _LibConfig_H REGEX "${_LibConfig_H_REGEX}")
else()
  set(_LibConfig_H "")
endif()
foreach(c MAJOR MINOR REVISION)
  if(_LibConfig_H MATCHES "#[ \t]*define[ \t]+LIBCONFIG_VER_${c}[ \t]+([0-9]+)")
    set(_LibConfig_VERSION_${c} "${CMAKE_MATCH_1}")
  else()
    unset(_LibConfig_VERSION_${c})
  endif()
endforeach()
if(DEFINED _LibConfig_VERSION_MAJOR AND DEFINED _LibConfig_VERSION_MINOR)
  set(LibConfig_VERSION_MAJOR "${_LibConfig_VERSION_MAJOR}")
  set(LibConfig_VERSION_MINOR "${_LibConfig_VERSION_MINOR}")
  set(LibConfig_VERSION "${LibConfig_VERSION_MAJOR}.${LibConfig_VERSION_MINOR}")
  if(DEFINED _LibConfig_VERSION_REVISION)
    set(LibConfig_VERSION_PATCH "${_LibConfig_VERSION_REVISION}")
    set(LibConfig_VERSION "${LibConfig_VERSION}.${LibConfig_VERSION_PATCH}")
  else()
    unset(LibConfig_VERSION_PATCH)
  endif()
else()
  set(LibConfig_VERSION_MAJOR "")
  set(LibConfig_VERSION_MINOR "")
  set(LibConfig_VERSION_PATCH "")
  set(LibConfig_VERSION "")
endif()
unset(_LibConfig_VERSION_MAJOR)
unset(_LibConfig_VERSION_MINOR)
unset(_LibConfig_VERSION_REVISION)
unset(_LibConfig_H_REGEX)
unset(_LibConfig_H)

#-----------------------------------------------------------------------------
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibConfig
  FOUND_VAR LibConfig_FOUND
  REQUIRED_VARS LibConfig_LIBRARY LibConfig_INCLUDE_DIR
  VERSION_VAR LibConfig_VERSION
  )
set(LIBCONFIG_FOUND ${LibConfig_FOUND})

#-----------------------------------------------------------------------------
# Provide documented result variables and targets.
if(LibConfig_FOUND)
  set(LibConfig_INCLUDE_DIRS ${LibConfig_INCLUDE_DIR})
  set(LibConfig_LIBRARIES ${LibConfig_LIBRARY})
  if(NOT TARGET LibConfig::LibConfig)
    add_library(LibConfig::LibConfig UNKNOWN IMPORTED)
    set_target_properties(LibConfig::LibConfig PROPERTIES
      IMPORTED_LOCATION "${LibConfig_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${LibConfig_INCLUDE_DIRS}"
      )
  endif()
endif()
