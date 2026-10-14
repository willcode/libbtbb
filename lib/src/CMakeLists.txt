#
# This file is part of Libbtbb.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#
# Based slightly upon the hackrf cmake setup.

include(${PROJECT_SOURCE_DIR}/../cmake/set_release.cmake)
add_definitions( -DRELEASE="${RELEASE_STRING}" )
message(STATUS "Setting version string ${RELEASE_STRING}")

# Source
set(c_sources ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_packet.c
              ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_piconet.c
              ${CMAKE_CURRENT_SOURCE_DIR}/bluetooth_le_packet.c
              ${CMAKE_CURRENT_SOURCE_DIR}/companies.c
              ${CMAKE_CURRENT_SOURCE_DIR}/pcap.c
              ${CMAKE_CURRENT_SOURCE_DIR}/pcapng.c
              ${CMAKE_CURRENT_SOURCE_DIR}/pcapng-bt.c
			  CACHE INTERNAL "List of C sources")
set(c_headers ${CMAKE_CURRENT_SOURCE_DIR}/btbb.h
			  CACHE INTERNAL "List of C headers")

if(NOT BUILD_SHARED_LIB AND NOT BUILD_STATIC_LIB)
	message( FATAL_ERROR "Not building static or shared library - at least one must be built")
endif()

set(CMAKE_MACOSX_RPATH 1)

if( ${BUILD_SHARED_LIB} )
    # Shared library
    message(STATUS "Building shared library")
    add_library(btbb SHARED ${c_sources})
    set_target_properties(btbb PROPERTIES VERSION ${MAJOR_VERSION}.${MINOR_VERSION} SOVERSION 1)
    set_target_properties(btbb PROPERTIES CLEAN_DIRECT_OUTPUT 1)
    # Only export the public btbb_*/lell_* API (plus the historical
    # bt_compidtostr) from the shared library; keep internal helpers with
    # generic names (hop, fhs, DM, count_bits, ...) out of the global
    # symbol namespace.
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND NOT APPLE AND NOT WIN32)
        set(BTBB_VERSION_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/libbtbb.map)
        target_link_options(btbb PRIVATE "LINKER:--version-script=${BTBB_VERSION_SCRIPT}")
        set_target_properties(btbb PROPERTIES LINK_DEPENDS ${BTBB_VERSION_SCRIPT})
    endif()
    install(TARGETS btbb
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            COMPONENT sharedlibs)
endif( ${BUILD_SHARED_LIB} )

if( ${BUILD_STATIC_LIB} )
    # Static library
    message(STATUS "Building static library")
    add_library(btbb-static STATIC ${c_sources})
    set_target_properties(btbb-static PROPERTIES OUTPUT_NAME "btbb")
    set_target_properties(btbb-static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
    install(TARGETS btbb-static
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            COMPONENT staticlibs)
endif( ${BUILD_STATIC_LIB} )

install(FILES ${c_headers}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        COMPONENT headers
        )
