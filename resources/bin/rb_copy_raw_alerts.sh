#!/bin/bash

#######################################################################
# Copyright (c) 2025 ENEO Tecnología S.L.
# This file is part of redBorder.
# redBorder is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# redBorder is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License License for more details.
# You should have received a copy of the GNU Affero General Public License License
# along with redBorder. If not, see <http://www.gnu.org/licenses/>.
#######################################################################

find /etc/snort -type d \( -path '*/raw*' -o -path '*/.*' \) -prune -o -type d -print | while read src_dir; do
cd "$src_dir" || continue

files=$(ls *_alert_full.txt 2>/dev/null)
[ -z "$files" ] && continue

raw_dir="$src_dir/raw"
dest_dir="$raw_dir/$(date +%Y-%m%d_%H)"

mkdir -p "$dest_dir"

for file in $files; do
    [ -e "$file" ] || continue

    base_name="$(basename "$file")"
    name="${base_name%.*}"
    ext="${base_name##*.}"

    dest_file="$dest_dir/$base_name"

    if [ -e "$dest_file" ]; then
    i=1
    while [ -e "$dest_dir/${name}_$i.$ext" ]; do
        i=$((i + 1))
    done
    dest_file="$dest_dir/${name}_$i.$ext"
    fi

    cp -f "$file" "$dest_file"
    : > "$file"
    echo "Copied $file to $dest_file and truncated original"
done

find "$dest_dir" -type f -size 0 -name '*.txt' -delete
done