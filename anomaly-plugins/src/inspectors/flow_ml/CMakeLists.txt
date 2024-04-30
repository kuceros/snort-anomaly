cmake_minimum_required ( VERSION 3.4.3 )
project ( flow_ml CXX )

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
    flow_ml MODULE
    flow_ml.cc
    flow_ml.h
    flow_ml_event_handler.cc
    flow_ml_event_handler.h
)

if ( APPLE )
    set_target_properties (
        flow_ml
            PROPERTIES
                LINK_FLAGS "-undefined dynamic_lookup"
                INSTALL_RPATH "/usr/local/lib"
    )
endif ( APPLE )

set_target_properties (
    flow_ml
        PROPERTIES
            PREFIX ""
)

target_include_directories (
    flow_ml PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)
target_link_libraries(
    flow_ml
    ml
)

install (
    TARGETS flow_ml
    LIBRARY
        DESTINATION "${INSPECTOR_INSTALL_PATH}"
)
