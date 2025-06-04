#!/usr/bin/env ruby

#######################################################################
## Copyright (c) 2025 ENEO Tecnología S.L.
## This file is part of redBorder.
## redBorder is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
## redBorder is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Affero General Public License License for more details.
## You should have received a copy of the GNU Affero General Public License License
## along with redBorder. If not, see <http://www.gnu.org/licenses/>.
########################################################################
require 'open3'

RED    = "\e[0;31m"
GREEN  = "\e[0;32m"
YELLOW = "\e[1;33m"
BLUE   = "\e[0;34m"
NC     = "\e[0m"
CHECK  = "✔"
CROSS  = "✖"

BASE_DIR            = "/etc/snort"
SNORT_SERVICE_PREFX = "snort3@"

def visible_length(str)
  str.gsub(/\e\[[\d;]*m/, '').length
end

def pad_ansi(str_with_ansi, target_width)
  current = visible_length(str_with_ansi)
  if current < target_width
    str_with_ansi + " " * (target_width - current)
  else
    str_with_ansi
  end
end

groups = Dir.entries(BASE_DIR).select do |ent|
  path = File.join(BASE_DIR, ent)
  File.directory?(path) && ent =~ /^\d+_.+$/
end.sort

rows = []

groups.each do |grp|
  result = {
    group: grp,
    svc:   "DOWN",
    rules: "MISSING",
    count: "--",
    pid:   "--"
  }

  svc_name = "#{SNORT_SERVICE_PREFX}#{grp}"
  out, _err, status = Open3.capture3("service #{svc_name} status")
  if out =~ /Active:\s+active \(running\)/
    result[:svc] = "UP"
    if out =~ /Main PID:\s+(\d+)/
      result[:pid] = $1
    end
  end

  rules_file = File.join(BASE_DIR, grp, "snort.rules")
  if File.exist?(rules_file) && File.size(rules_file) > 0
    result[:rules] = "LOADED"
    alert_lines = `grep -c '^alert' "#{rules_file}"`.strip
    result[:count] = alert_lines.empty? ? "0" : alert_lines
  end

  rows << result
end

group_w = "Group".length
svc_w   = "Service".length
rules_w = "Rules".length
count_w = "Count".length
pid_w   = "PID".length

rows.each do |h|
  group_w = [ group_w, h[:group].length ].max

  disp_svc = (h[:svc] == "UP" ? "#{CHECK} UP" : "#{CROSS} DOWN")
  svc_w = [ svc_w, visible_length(disp_svc) ].max

  disp_rules = h[:rules]
  rules_w = [ rules_w, visible_length(disp_rules) ].max

  count_w = [ count_w, h[:count].length ].max

  pid_w = [ pid_w, h[:pid].length ].max
end

header = []
header << "Group".ljust(group_w)
header << "Service".ljust(svc_w)
header << "Rules".ljust(rules_w)
header << "Count".ljust(count_w)
header << "PID".ljust(pid_w)
header_line = "║ #{header.join(" │ ")} ║"
line_len    = visible_length(header_line)

top_border    = "╔" + ("═" * (line_len - 2)) + "╗"
separator     = "╟" + ("─" * (line_len - 2)) + "╢"
bottom_border = "╚" + ("═" * (line_len - 2)) + "╝"

puts "#{BLUE}#{top_border}#{NC}"
title = "SNORT3 STATUS DASHBOARD"
inner = line_len - 2
left_pad  = (inner - title.length) / 2
right_pad = inner - title.length - left_pad
puts "#{BLUE}║#{' ' * left_pad}#{title}#{' ' * right_pad}║#{NC}"
puts "#{BLUE}#{separator}#{NC}"

puts header_line
puts separator

rows.each do |h|
  col_group = h[:group].ljust(group_w)

  if h[:svc] == "UP"
    raw_svc    = "#{CHECK} UP"
    color_code = GREEN
  else
    raw_svc    = "#{CROSS} DOWN"
    color_code = RED
  end
  
  colored_svc   = "#{color_code}#{raw_svc}#{NC}"
  padded_svc    = pad_ansi(colored_svc, svc_w)
  
  if h[:rules] == "LOADED"
    raw_rules   = "LOADED"
    color_rules = GREEN
  else
    raw_rules   = "MISSING"
    color_rules = YELLOW
  end
  
  colored_rules = "#{color_rules}#{raw_rules}#{NC}"
  
  padded_rules  = pad_ansi(colored_rules, rules_w)
  padded_count = h[:count].ljust(count_w)
  padded_pid   = h[:pid].ljust(pid_w)
  
  puts "║ #{col_group} │ #{padded_svc} │ #{padded_rules} │ #{padded_count} │ #{padded_pid} ║"
end

puts "#{BLUE}#{bottom_border}#{NC}"
