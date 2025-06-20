#!/usr/bin/env ruby

#######################################################################
# Copyright (c) 2025 ENEO Tecnologia S.L.
# This file is part of redBorder.
# redBorder is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# redBorder is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with redBorder. If not, see <http://www.gnu.org/licenses/>.
#######################################################################

CLASSIFICATION_REGEX = /classtype:\s*([^\s;]+)\s*;/

DEFAULT_CLASSIFICATIONS = {
  'not-suspicious' => 3, 'unknown' => 3, 'bad-unknown' => 2, 'attempted-recon' => 2,
  'successful-recon-limited' => 2, 'successful-recon-largescale' => 2, 'attempted-dos' => 2,
  'successful-dos' => 2, 'attempted-user' => 1, 'unsuccessful-user' => 1, 'successful-user' => 1,
  'attempted-admin' => 1, 'successful-admin' => 1, 'rpc-portmap-decode' => 2,
  'shellcode-detect' => 1, 'string-detect' => 3, 'suspicious-filename-detect' => 2,
  'suspicious-login' => 2, 'system-call-detect' => 2, 'tcp-connection' => 4,
  'trojan-activity' => 1, 'unusual-client-port-connection' => 2, 'network-scan' => 3,
  'denial-of-service' => 2, 'non-standard-protocol' => 2, 'protocol-command-decode' => 3,
  'web-application-activity' => 2, 'web-application-attack' => 1, 'misc-activity' => 3,
  'misc-attack' => 2, 'icmp-event' => 3, 'inappropriate-content' => 1,
  'policy-violation' => 1, 'default-login-attempt' => 2, 'sdf' => 2, 'file-format' => 1,
  'malware-cnc' => 1, 'client-side-exploit' => 1
}

NO_COLOR = ARGV.delete('--no-color')
USE_COLOR = !NO_COLOR

def color(text, code)
  USE_COLOR ? "\e[#{code}m#{text}\e[0m" : text
end

def log_info(message)
  puts "#{color('[INFO]', 34)} #{message}"
end

def log_success(message)
  puts "#{color('[SUCCESS]', 32)} #{message}"
end

def log_warn(message)
  puts "#{color('[WARN]', 33)} #{message}"
end

def load_classifications(conf_file)
  classifications = {}
  File.open(conf_file).each_line do |line|
    next unless line.start_with?('config classification:')
    data = line.sub('config classification:', '').strip
    parts = data.split(',', 3)
    shortname = parts[0].strip
    priority = parts[2].strip.to_i
    classifications[shortname] = priority
  end
  classifications
end

def remap_ruleset(rule_file, classifications)
  remapped_count = 0
  not_mapped_count = 0
  used_classifications = Hash.new(0)
  unknown_priority = classifications['unknown'] || 3
  not_mapped_rules = []

  log_info("Processing rules from #{rule_file}...")

  updated_lines = File.readlines(rule_file).map do |rule|
    if m = rule.match(CLASSIFICATION_REGEX)
      classtype = m[1]
      if classifications.key?(classtype)
        priority = classifications[classtype]
        rule = rule.sub(/\)\s*$/, " priority:#{priority};)")
        remapped_count += 1
        used_classifications[classtype] += 1
      else
        rule = rule.sub(/\)\s*$/, " priority:#{unknown_priority};)")
        not_mapped_count += 1
        used_classifications['unknown'] += 1
        not_mapped_rules << rule.chomp
      end
    else
      not_mapped_count += 1
      not_mapped_rules << rule.chomp
    end
    rule
  end

  File.write(rule_file, updated_lines.join("\n") + "\n")

  log_success("Remapping completed.")
  log_info("Rules updated: #{remapped_count}")
  log_info("Rules not mapped (assigned unknown priority): #{not_mapped_count}")
  if not_mapped_rules.any?
    log_warn("List of rules not mapped:")
    not_mapped_rules.each do |r|
      puts r
    end
  end
  log_info("Classifications applied: #{used_classifications.keys.size}")
  used_classifications.each do |type, count|
    log_info(" - #{type}: #{count}")
  end
end

if ARGV.length == 1
  rule_file = ARGV[0]
  log_info("Using default classifications.")
  classifications = DEFAULT_CLASSIFICATIONS
elsif ARGV.length == 2
  conf_file, rule_file = ARGV
  log_info("Loading classifications from #{conf_file}...")
  custom = load_classifications(conf_file)
  classifications = DEFAULT_CLASSIFICATIONS.merge(custom)
else
  puts "#{color('[ERROR]', 31)} Usage: #{$0} [--no-color] [classification_conf] <rule_file>"
  exit
end

remap_ruleset(rule_file, classifications)