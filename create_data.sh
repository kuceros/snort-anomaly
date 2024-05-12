#!/bin/bash

# create_data.sh
#
# This script processes all files in the specified 
# directory and runs Snort on them.
#
# Usage: create_data.sh <path_to_top_folder>
# Rostislav Kucera <kucera.rosta@gmail.com>, 2024

process_files() {
    local folder="$1"
    local snort_command="$2"
    for file in "$folder"/*; do
        if [[ -f "$file" ]]; then
            execute_snort "$snort_command" "$file"
        fi
    done
}

execute_snort() {
    local snort_command="$1"
    local file="$2"
    eval "$snort_command -r \"$file\""
}

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <path_to_top_folder>"
    exit 1
fi

if [[ ! -d "$1" ]]; then
    echo "Error: $1 is not a valid directory."
    exit 1
fi

snort_command="snort -c \"/usr/local/etc/snort/snort.lua\" --plugin-path \"/usr/local/snort/lib/snort/plugins/extra/\" -q >/dev/null 2>&1"

for subdirectory1 in "$1"/*; do
    if [[  -d "$subdirectory1" ]]; then
        if [[ "$(basename "$subdirectory1")" != "captures3" ]]; then
            for subdirectory2 in "$subdirectory1"/*; do
                if [[ -d "$subdirectory2" ]]; then
                    # Process files in each subdirectory
                    process_files "$subdirectory2" "$snort_command"
                fi
            done
        fi
    fi
done
