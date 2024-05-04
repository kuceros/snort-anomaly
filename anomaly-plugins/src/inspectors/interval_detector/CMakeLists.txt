cmake_minimum_required ( VERSION 3.4.3 )
project ( interval_detector CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

link_directories(/usr/local/lib)

add_library (
    interval_detector MODULE
    interval_detector.cc
    interval_detector.h
    interval_detector_event_handler.cc
    interval_detector_event_handler.h
)

if ( APPLE )
    set_target_properties (
        interval_detector
            PROPERTIES
                LINK_FLAGS "-undefined dynamic_lookup"
                INSTALL_RPATH "/usr/local/lib"
    )
endif ( APPLE )

set_target_properties (
    interval_detector
        PROPERTIES
            PREFIX ""
)

target_include_directories (
    interval_detector PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)
target_link_libraries(
    interval_detector
    maxminddb
)

install (
    TARGETS interval_detector
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)
