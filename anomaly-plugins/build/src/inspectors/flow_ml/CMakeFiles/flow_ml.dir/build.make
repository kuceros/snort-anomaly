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
include src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/compiler_depend.make

# Include the progress variables for this target.
include src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/progress.make

# Include the compile flags for this target's objects.
include src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flags.make

src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml.cc.o: src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flags.make
src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml.cc.o: /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/inspectors/flow_ml/flow_ml.cc
src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml.cc.o: src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml.cc.o"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml.cc.o -MF CMakeFiles/flow_ml.dir/flow_ml.cc.o.d -o CMakeFiles/flow_ml.dir/flow_ml.cc.o -c /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/inspectors/flow_ml/flow_ml.cc

src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/flow_ml.dir/flow_ml.cc.i"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/inspectors/flow_ml/flow_ml.cc > CMakeFiles/flow_ml.dir/flow_ml.cc.i

src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/flow_ml.dir/flow_ml.cc.s"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/inspectors/flow_ml/flow_ml.cc -o CMakeFiles/flow_ml.dir/flow_ml.cc.s

src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.o: src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flags.make
src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.o: /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/inspectors/flow_ml/flow_ml_event_handler.cc
src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.o: src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.o"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.o -MF CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.o.d -o CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.o -c /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/inspectors/flow_ml/flow_ml_event_handler.cc

src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.i"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/inspectors/flow_ml/flow_ml_event_handler.cc > CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.i

src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.s"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/inspectors/flow_ml/flow_ml_event_handler.cc -o CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.s

# Object files for target flow_ml
flow_ml_OBJECTS = \
"CMakeFiles/flow_ml.dir/flow_ml.cc.o" \
"CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.o"

# External object files for target flow_ml
flow_ml_EXTERNAL_OBJECTS =

src/inspectors/flow_ml/flow_ml.so: src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml.cc.o
src/inspectors/flow_ml/flow_ml.so: src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/flow_ml_event_handler.cc.o
src/inspectors/flow_ml/flow_ml.so: src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/build.make
src/inspectors/flow_ml/flow_ml.so: src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX shared module flow_ml.so"
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/flow_ml.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/build: src/inspectors/flow_ml/flow_ml.so
.PHONY : src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/build

src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/clean:
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml && $(CMAKE_COMMAND) -P CMakeFiles/flow_ml.dir/cmake_clean.cmake
.PHONY : src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/clean

src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/depend:
	cd /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82 /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/src/inspectors/flow_ml /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml /Users/kucera.rosta/Desktop/Materialy/DP/snort3-extra_82/build/src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/inspectors/flow_ml/CMakeFiles/flow_ml.dir/depend

