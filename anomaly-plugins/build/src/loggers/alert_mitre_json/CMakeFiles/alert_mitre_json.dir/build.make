# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.29

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.29.0/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.29.0/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build

# Include any dependencies generated for this target.
include src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/compiler_depend.make

# Include the progress variables for this target.
include src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/progress.make

# Include the compile flags for this target's objects.
include src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/flags.make

src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.o: src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/flags.make
src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.o: /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/loggers/alert_mitre_json/alert_mitre_json.cc
src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.o: src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.o"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/loggers/alert_mitre_json && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.o -MF CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.o.d -o CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.o -c /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/loggers/alert_mitre_json/alert_mitre_json.cc

src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.i"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/loggers/alert_mitre_json && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/loggers/alert_mitre_json/alert_mitre_json.cc > CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.i

src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.s"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/loggers/alert_mitre_json && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/loggers/alert_mitre_json/alert_mitre_json.cc -o CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.s

# Object files for target alert_mitre_json
alert_mitre_json_OBJECTS = \
"CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.o"

# External object files for target alert_mitre_json
alert_mitre_json_EXTERNAL_OBJECTS =

src/loggers/alert_mitre_json/alert_mitre_json.so: src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/alert_mitre_json.cc.o
src/loggers/alert_mitre_json/alert_mitre_json.so: src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/build.make
src/loggers/alert_mitre_json/alert_mitre_json.so: /usr/local/lib/libmaxminddb.dylib
src/loggers/alert_mitre_json/alert_mitre_json.so: src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared module alert_mitre_json.so"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/loggers/alert_mitre_json && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/alert_mitre_json.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/build: src/loggers/alert_mitre_json/alert_mitre_json.so
.PHONY : src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/build

src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/clean:
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/loggers/alert_mitre_json && $(CMAKE_COMMAND) -P CMakeFiles/alert_mitre_json.dir/cmake_clean.cmake
.PHONY : src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/clean

src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/depend:
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82 /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/loggers/alert_mitre_json /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/loggers/alert_mitre_json /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/loggers/alert_mitre_json/CMakeFiles/alert_mitre_json.dir/depend

