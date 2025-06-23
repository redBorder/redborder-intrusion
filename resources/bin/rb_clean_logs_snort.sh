#!/bin/bash

BASE_DIR="/etc/snort"

find "$BASE_DIR" -maxdepth 1 -mindepth 1 -type d | while read -r instance_dir; do
  dir_name=$(basename "$instance_dir")

  if [[ "$(grep -o '_' <<< "$dir_name" | wc -l)" -eq 2 ]]; then
    RAW_DIR="$instance_dir/raw"

    if [ -d "$RAW_DIR" ]; then
      echo "Cleaning $RAW_DIR ..."

      find "$RAW_DIR" -maxdepth 1 -mindepth 1 -type d -mtime +30 -exec rm -rf {} \;
    fi
  fi
done
