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
include src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/compiler_depend.make

# Include the progress variables for this target.
include src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/progress.make

# Include the compile flags for this target's objects.
include src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/flags.make

src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/sid_18758.cc.o: src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/flags.make
src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/sid_18758.cc.o: /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/so_rules/sid_18758/sid_18758.cc
src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/sid_18758.cc.o: src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/sid_18758.cc.o"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/so_rules/sid_18758 && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/sid_18758.cc.o -MF CMakeFiles/sid_18758.dir/sid_18758.cc.o.d -o CMakeFiles/sid_18758.dir/sid_18758.cc.o -c /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/so_rules/sid_18758/sid_18758.cc

src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/sid_18758.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/sid_18758.dir/sid_18758.cc.i"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/so_rules/sid_18758 && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/so_rules/sid_18758/sid_18758.cc > CMakeFiles/sid_18758.dir/sid_18758.cc.i

src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/sid_18758.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/sid_18758.dir/sid_18758.cc.s"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/so_rules/sid_18758 && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/so_rules/sid_18758/sid_18758.cc -o CMakeFiles/sid_18758.dir/sid_18758.cc.s

# Object files for target sid_18758
sid_18758_OBJECTS = \
"CMakeFiles/sid_18758.dir/sid_18758.cc.o"

# External object files for target sid_18758
sid_18758_EXTERNAL_OBJECTS =

src/so_rules/sid_18758/sid_18758.so: src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/sid_18758.cc.o
src/so_rules/sid_18758/sid_18758.so: src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/build.make
src/so_rules/sid_18758/sid_18758.so: src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared module sid_18758.so"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/so_rules/sid_18758 && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sid_18758.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/build: src/so_rules/sid_18758/sid_18758.so
.PHONY : src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/build

src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/clean:
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/so_rules/sid_18758 && $(CMAKE_COMMAND) -P CMakeFiles/sid_18758.dir/cmake_clean.cmake
.PHONY : src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/clean

src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/depend:
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82 /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/so_rules/sid_18758 /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/so_rules/sid_18758 /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/so_rules/sid_18758/CMakeFiles/sid_18758.dir/depend

