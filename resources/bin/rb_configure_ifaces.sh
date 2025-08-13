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

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
RESET="\033[0m"
BOLD="\033[1m"

log_success() {
    echo -e "${GREEN}[ OK ]${RESET} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${RESET} $1"
}

log_info() {
    echo -e "${YELLOW}[INFO]${RESET} $1"
}

for dir in /etc/snort/*; do
  if [ -d "$dir" ]; then

    if [ -f "$dir/.ethtool_configured" ]; then
      log_info "Skipping $dir, already configured."
      continue
    fi

    env_file="$dir/env"
    if [ -f "$env_file" ]; then
      IFACE=$(cat "$env_file" | grep -E '^IFACE=' | cut -d'=' -f2)

      if [[ "$IFACE" == *":"* ]]; then
        log_info "Found interface pair in $env_file: $IFACE"
        pair=(${IFACE//:/ })
        iface1="${pair[0]}"
        iface2="${pair[1]}"
      else
        log_info "Found single interface in $env_file: $IFACE"
        iface1="$IFACE"
        iface2=""
      fi

      log_info "Configuring interface: $iface1"
      if [ -n "$iface1" ]; then
        if ethtool -K "$iface1" gro off lro off 2>/dev/null; then
          log_success "Successfully configured $iface1"
        else
          log_fail "Failed to configure $iface1"
        fi
      fi

      if [ -n "$iface2" ]; then
        log_info "Configuring interface: $iface2"
        if ethtool -K "$iface2" gro off lro off 2>/dev/null; then
          log_success "Successfully configured $iface2"
        else
          log_fail "Failed to configure $iface2"
        fi
      fi

      touch "$dir/.ethtool_configured"
    fi
  fi
done
