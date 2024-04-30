# This file will be configured to contain variables for CPack. These variables
# should be set in the CMake list file of the project before CPack module is
# included. The list of available CPACK_xxx variables and their associated
# documentation may be obtained using
#  cpack --help-variable-list
#
# Some variables are common to all generators (e.g. CPACK_PACKAGE_NAME)
# and some are specific to a generator
# (e.g. CPACK_NSIS_EXTRA_INSTALL_COMMANDS). The generator specific variables
# usually begin with CPACK_<GENNAME>_xxxx.


set(CPACK_BUILD_SOURCE_DIRS "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82;/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build")
set(CPACK_CMAKE_GENERATOR "Unix Makefiles")
set(CPACK_COMPONENTS_ALL "")
set(CPACK_COMPONENT_UNSPECIFIED_HIDDEN "TRUE")
set(CPACK_COMPONENT_UNSPECIFIED_REQUIRED "TRUE")
set(CPACK_DEFAULT_PACKAGE_DESCRIPTION_FILE "/usr/local/Cellar/cmake/3.29.0/share/cmake/Templates/CPack.GenericDescription.txt")
set(CPACK_DEFAULT_PACKAGE_DESCRIPTION_SUMMARY "extra built using CMake")
set(CPACK_DMG_SLA_USE_RESOURCE_FILE_LICENSE "ON")
set(CPACK_GENERATOR "TGZ")
set(CPACK_INNOSETUP_ARCHITECTURE "x64")
set(CPACK_INSTALL_CMAKE_PROJECTS "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build;extra;ALL;/")
set(CPACK_INSTALL_PREFIX "/usr/local/snort")
set(CPACK_MODULE_PATH "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/cmake")
set(CPACK_NSIS_DISPLAY_NAME "snort")
set(CPACK_NSIS_INSTALLER_ICON_CODE "")
set(CPACK_NSIS_INSTALLER_MUI_ICON_CODE "")
set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES")
set(CPACK_NSIS_PACKAGE_NAME "snort")
set(CPACK_NSIS_UNINSTALL_NAME "Uninstall")
set(CPACK_OBJDUMP_EXECUTABLE "/Library/Developer/CommandLineTools/usr/bin/objdump")
set(CPACK_OSX_SYSROOT "/Library/Developer/CommandLineTools/SDKs/MacOSX14.4.sdk")
set(CPACK_OUTPUT_CONFIG_FILE "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CPackConfig.cmake")
set(CPACK_PACKAGE_DEFAULT_LOCATION "/")
set(CPACK_PACKAGE_DESCRIPTION_FILE "/usr/local/Cellar/cmake/3.29.0/share/cmake/Templates/CPack.GenericDescription.txt")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "extra built using CMake")
set(CPACK_PACKAGE_FILE_NAME "snort_extra-1.0.0-Darwin")
set(CPACK_PACKAGE_ICON "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/doc/images/snort.png")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "snort")
set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "snort")
set(CPACK_PACKAGE_NAME "snort_extra")
set(CPACK_PACKAGE_RELOCATABLE "true")
set(CPACK_PACKAGE_VENDOR "Cisco")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_RESOURCE_FILE_LICENSE "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/LICENSE")
set(CPACK_RESOURCE_FILE_README "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/README")
set(CPACK_RESOURCE_FILE_WELCOME "/usr/local/Cellar/cmake/3.29.0/share/cmake/Templates/CPack.GenericWelcome.txt")
set(CPACK_SET_DESTDIR "OFF")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/*")
set(CPACK_SOURCE_OUTPUT_CONFIG_FILE "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CPackSourceConfig.cmake")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "snort_extra-1.0.0")
set(CPACK_SYSTEM_NAME "Darwin")
set(CPACK_THREADS "1")
set(CPACK_TOPLEVEL_TAG "Darwin")
set(CPACK_WIX_SIZEOF_VOID_P "8")

if(NOT CPACK_PROPERTIES_FILE)
  set(CPACK_PROPERTIES_FILE "/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CPackProperties.cmake")
endif()

if(EXISTS ${CPACK_PROPERTIES_FILE})
  include(${CPACK_PROPERTIES_FILE})
endif()
