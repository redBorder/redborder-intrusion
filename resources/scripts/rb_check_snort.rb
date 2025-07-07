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
require 'optparse'

RED    = "\e[0;31m"
GREEN  = "\e[0;32m"
YELLOW = "\e[1;33m"
BLUE   = "\e[0;34m"
NC     = "\e[0m"
WHITE = "\e[97m"
CHECK  = "✔"
CROSS  = "✖"
BLACK = "\e[38;2;50;50;50m"

BASE_DIR            = "/etc/snort"
SNORT_SERVICE_PREFX = "snort3@"

options = {
  show_ascii: false,
}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: rb_check_snort.rb [--show-ascii]"
  opts.on('-h', '--help', 'Show this help message') do
    puts opt
    exit
  end
  opts.on('-s', '--show-ascii', 'Run with redBorder logo') do
    options[:show_ascii] = true
  end

end

begin
  parser.parse!(ARGV)
rescue OptionParser::InvalidOption, OptionParser::MissingArgument => e
  warn e.message
  puts parser
  exit 1
end

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

def pick_one_iface(iface_str)
  ifaces = iface_str.split(':').map(&:strip).reject(&:empty?)
  ifaces.sample || iface_str
end

def get_segment_from_iface(iface)
  ip_output, _err, _status = Open3.capture3("ip a")

  ip_output.each_line do |line|
    if line =~ /^\d+: #{Regexp.escape(iface)}:.*master (\S+)/
      return $1.strip
    elsif line =~ /^\d+: #{Regexp.escape(iface)}:/
      return iface
    end
  end

  iface
end


groups = Dir.entries(BASE_DIR).select do |ent|
  path = File.join(BASE_DIR, ent)
  File.directory?(path) && ent =~ /^\d+_.+$/
end.sort

groups_data = {}

groups.each do |grp|
  if grp =~ /^(\d+)_(.+)_(.+)$/
    gid, gname, bindid = $1, $2, $3
  else
    gid, gname, bindid = grp, "", ""
  end
  groups_data[gid] ||= { group_name: gname, bindings: [] }
  groups_data[gid][:bindings] << { binding_id: bindid, full_group: grp }
end

results_by_group = {}

groups_data.each do |gid, info|
  gname = info[:group_name]
  results_by_group[gid] ||= { group_name: gname, bindings: {} }

  info[:bindings].each do |bind|
    grp = bind[:full_group]
    bindid = bind[:binding_id]

    result = {
      svc:      "DOWN",
      rules:    "MISSING",
      count:    "--",
      pid:      "--",
      mode:     "--",
      inline:   "--",
      cpu_cores:"--",
      threads:  "--",
      iface:    "--",
      segment:  "--",
      bp_support: CROSS,
      bp_enabled: CROSS
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
      total_rules = `grep -v '^\s*$' "#{rules_file}" | grep -v '^\s*#' | wc -l`.strip
      result[:count] = total_rules.empty? ? "0" : total_rules
    end

    env_file = File.join(BASE_DIR, grp, "env")
    if File.exist?(env_file)
      File.foreach(env_file) do |line|
        line.strip!
        next if line.empty? || line.start_with?("#")

        case line
        when /^MODE=(.+)$/
          result[:mode] = $1.strip
        when /^INLINE=(.+)$/
          inline = $1.strip
          if inline == "true"
            result[:inline] = "#{GREEN}#{CHECK}#{NC}" 
          else
            result[:inline] = "#{RED}#{CROSS}#{NC}"
          end
        when /^CPU_CORES=(.+)$/
          result[:cpu_cores] = $1.strip
        when /^THREADS=(.+)$/
          result[:threads] = $1.strip
        when /^IFACE=(.+)$/
          result[:iface] = $1.strip
        end
      end
    end

    selected_iface = pick_one_iface(result[:iface])
    segment = get_segment_from_iface(selected_iface)
    if segment && !segment.empty?
      result[:segment] = segment
      if segment.start_with?("bpbr")
        result[:bp_support] = "#{GREEN}#{CHECK}#{NC}"
        bypass_output, _err, _status = Open3.capture3("/usr/lib/redborder/bin/rb_bypass.sh -b #{segment} -g")
        if bypass_output =~ /non-Bypass mode/i
          result[:bp_enabled] = "#{YELLOW}non-bp!#{NC}"
        else
          result[:bp_enabled] = "#{GREEN}bp #{CHECK}#{NC}"
        end
      else
        result[:bp_support] = "#{RED}#{CROSS}#{NC}"
        result[:bp_enabled] = "#{YELLOW}non-bp!#{NC}"
      end
    else
      result[:bp_support] = "#{RED}#{CROSS}#{NC}"
      result[:bp_enabled] = "#{YELLOW}non-bp!#{NC}"
    end

    results_by_group[gid][:bindings][bindid] = result
  end
end

group_id_w   = "Group ID".length
group_name_w = "Group Name".length
bind_id_w    = "Binding ID".length
svc_w        = "Service".length
rules_w      = "Rules".length
count_w      = "Rule Count".length
pid_w        = "PID".length
mode_w       = "Mode".length
inline_w     = "Inline".length
cpu_cores_w  = "CPU_CORES".length
threads_w    = "Threads".length
iface_w      = "IFACE".length
segment_w    = "Segment".length
bp_support_w = "BP Support?".length
bp_enabled_w = "BP Enabled?".length

results_by_group.each do |gid, group_info|
  group_id_w   = [group_id_w, gid.length].max
  group_name_w = [group_name_w, group_info[:group_name].length].max

  group_info[:bindings].each do |bindid, h|
    bind_id_w    = [bind_id_w, bindid.length].max
    svc_text     = (h[:svc] == "UP" ? "#{CHECK} UP" : "#{CROSS} DOWN")
    svc_w        = [svc_w, visible_length(svc_text)].max
    rules_w      = [rules_w, visible_length(h[:rules])].max
    count_w      = [count_w, h[:count].length].max
    pid_w        = [pid_w, h[:pid].length].max
    mode_w       = [mode_w, h[:mode].length].max
    inline_w     = [inline_w, visible_length(h[:inline])].max
    cpu_cores_w  = [cpu_cores_w, h[:cpu_cores].length].max
    threads_w    = [threads_w, h[:threads].length].max
    iface_w      = [iface_w, h[:iface].length].max
    segment_w    = [segment_w, h[:segment].length].max
    bp_support_w = [bp_support_w, visible_length(h[:bp_support])].max
    bp_enabled_w = [bp_enabled_w, visible_length(h[:bp_enabled])].max
  end
end

header = []
header << "Group ID".ljust(group_id_w)
header << "Group Name".ljust(group_name_w)
header << "Binding ID".ljust(bind_id_w)
header << "Service".ljust(svc_w)
header << "Rules".ljust(rules_w)
header << "Rule Count".ljust(count_w)
header << "PID".ljust(pid_w)
header << "Mode".ljust(mode_w)
header << "Inline".ljust(inline_w)
header << "CPU_CORES".ljust(cpu_cores_w)
header << "Threads".ljust(threads_w)
header << "IFACE".ljust(iface_w)
header << "Segment".ljust(segment_w)
header << "BP Support?".ljust(bp_support_w)
header << "BP Enabled?".ljust(bp_enabled_w)

header_line = "│ #{header.join(" │ ")} │"
line_len    = visible_length(header_line)

top_border    = "╭" + ("─" * (line_len - 2)) + "╮"
separator     = "├" + ("─" * (line_len - 2)) + "┤"
bottom_border = "╰" + ("─" * (line_len - 2)) + "╯"

puts "#{BLUE}#{top_border}#{NC}"

show_ascii = true
if options[:show_ascii]
  title =""
  title += "          #{RED}JJJJJJJJJJJJJ#{NC}                                                                                                           \n"
  title += "       #{RED}JJJJJJJJJJJJJJJJJJJJ#{NC}                                                                                                       \n"
  title += "     #{RED}JJJJJJJJJJJJJJJJJJJJJJJJ#{NC}                                                                                                     \n"
  title += "    #{RED}JJJJJKLMLKKJJJJJJJJJJJJJJJ#{NC}                                                                                                    \n"
  title += "  #{RED}JJJJJLW#{NC}#{WHITE}OOOOO#{NC}#{RED}YQJJJJJJJJJJJJJJJ                                    JJJJ#{NC}EBBB                                  BBBA                 #{NC}\n"
  title += " #{RED}JJJJJLY#{NC}#{WHITE}OOOOOOO#{NC}#{RED}ZYOCDGJJJJJJJJJJJJ                                  JJJJ#{NC}JEBBB                                 BBBA                 \n"
  title += " #{RED}JJJJKN#{NC}#{WHITE}OOOOOOOO#{NC}#{BLACK}      #{NC}#{RED}EIJJJJJJJJJJ         JJJJJJJ  JJJJJJI    JJJJJJJJJ#{NC}EBBBBBBBBB    ABBBBBBA BBBBBBBA BBBBBBBBBA ABBBBBBA  BBBBBBBBB\n"
  title += "#{RED}JJJJJJKU#{NC}#{WHITE}OOOOOO#{NC}#{BLACK}        #{NC}#{RED}CHJJJJJJJJJ         JJJJJJJJJJ    JJIJJJJJJJJJJJJ#{NC}EBBBBBBBBBBB BBBBBBBBBBBBBBBBBBBBBBBBBBBBABBB     BBBBBBBBBABB\n"
  title += "#{RED}JJJJJJJKQ#{NC}#{WHITE}VX#{NC}ZZ#{NC}          #{NC}#{RED}EJJJJJJJJJJ        JJJJJ JJJJJJJJJJJJJJJ     JJJ#{NC}EBBBA    BBBBBBB    BBBBBBBA BBBBA   BBBBBBBBBBBBBBBBBBBA  \n"
  title += "#{RED}JJJJJJJJJIDG#{NC}#{WHITE}#{RED}G #{NC}         #{NC}#{RED}EJJJJJJJJJJ        JJJJ  JJJJJJJJJJJJJJJ     JJJ#{NC}EBBBA    ABBBBBB    BBBBBBBB BBBB    ABBBBBBBBBBBBBBABBB   \n"
  title += "#{RED}JJJJJJJJ#{NC}#{WHITE}LTZOOYQ#{NC}#{RED}#{NC}       #{NC}#{RED}CHJJJJJJJJJ         JJJJ   JJJJJ      JJJJJJJJJJJ#{NC}EBBBBBBBBBBBABBBBBABBBBABBBB  BBBBBBBBBBBBBBBB      BBBB   \n"
  title += "#{RED}JJJJJJK#{NC}#{WHITE}POOOOOOXL#{NC}#{RED}BBBBBDIJJJJJJJJJJ         JJJJJ    JJJJJJJJ    JJJJJJJJ#{NC}JEBBBBBBBBBB   ABBBBBBA ABBBA   BBBBBBBBBBA BBBBBBB BBBB   \n"
  title += "#{RED}JJJJJJJL#{NC}#{WHITE}WZOZZUD#{NC}#{RED}BBDGJJJJJJJJJJJJ#{NC}                                                                           #{RED}I#{NC}ntrusion #{RED}P#{NC}revention #{RED}S#{NC}ystem\n"                                                                                              
  title += "#{RED}  JJJJJJJKLMMKKJJJJJJJJJJJJJJJJ  #{NC} \n"                                                                                               
  title += "#{RED}   IJJJJJJJJJJJJJJJJJJJJJJJJJJ   #{NC}\n"                                                                                                 
  title += "#{RED}     JJJJJJJJJJJJJJJJJJJJJJJI  #{NC}\n"                                                                                                   
  title += "#{RED}       JJJJJJJJJJJJJJJJJJJJ  #{NC}\n"                                                                                                     
  title += "#{RED}          JJJJJJJJJJJJJ    #{NC}\n"                                                                                                       
  puts title
end
title = "Intrusion Sensor Status"
inner = line_len - 2
left_pad  = [0, (inner - title.length) / 2].max
right_pad = [0, inner - title.length - left_pad].max
puts "#{BLUE}│#{' ' * left_pad}#{title}#{' ' * right_pad}│#{NC}"
puts "#{BLUE}#{separator}#{NC}"

puts header_line
puts separator

results_by_group.each do |gid, group_info|
  gname = group_info[:group_name]
  first_binding = true

  group_info[:bindings].each do |bindid, h|
    col_gid = first_binding ? gid.ljust(group_id_w) : " " * group_id_w
    col_gname = first_binding ? gname.ljust(group_name_w) : " " * group_name_w
    first_binding = false

    bind_text = "├─ #{bindid}"
    bind_text = bind_text.ljust(bind_id_w)

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

    padded_count     = h[:count].ljust(count_w)
    padded_pid       = h[:pid].ljust(pid_w)
    padded_mode      = h[:mode].ljust(mode_w)
    padded_inline    = pad_ansi(h[:inline], inline_w)
    padded_cpu_cores = h[:cpu_cores].ljust(cpu_cores_w)
    padded_threads   = h[:threads].ljust(threads_w)
    padded_iface     = h[:iface].ljust(iface_w)
    padded_bp_support= pad_ansi(h[:bp_support], bp_support_w)
    padded_bp_enabled= pad_ansi(h[:bp_enabled], bp_enabled_w)
    padded_segment   = pad_ansi(h[:segment], segment_w)
    puts "│ #{col_gid} │ #{col_gname} │ #{bind_text} │ #{padded_svc} │ #{padded_rules} │ #{padded_count} │ #{padded_pid} │ #{padded_mode} │ #{padded_inline} │ #{padded_cpu_cores} │ #{padded_threads} │ #{padded_iface} │ #{padded_segment} │ #{padded_bp_support} │ #{padded_bp_enabled} │"
  end
end

puts "#{BLUE}#{bottom_border}#{NC}"