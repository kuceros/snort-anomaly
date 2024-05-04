cmake_minimum_required(VERSION 3.4.3)
project(alert_dos_json CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(APPLE)
    set(CMAKE_MACOSX_RPATH OFF)
endif(APPLE)

link_directories(/usr/local/lib)

add_library(
    alert_dos_json MODULE
    alert_dos_json.cc
)

if(APPLE)
    set_target_properties(
        alert_dos_json
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
            INSTALL_RPATH "/usr/local/lib"
    )
endif(APPLE)

set_target_properties(
    alert_dos_json
    PROPERTIES
        PREFIX ""
)

target_include_directories(
    alert_dos_json PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

target_link_libraries(
    alert_dos_json
    maxminddb
)

install(
    TARGETS alert_dos_json
    LIBRARY
        DESTINATION "${LOGGER_INSTALL_PATH}"
)
