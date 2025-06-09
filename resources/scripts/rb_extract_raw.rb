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

require 'optparse'
require 'pathname'

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: ruby rb_extract_raw.rb --uuid UUID files..."

  opts.on("--uuid UUID", String, "UUID to match (8-4-4-4-12)") do |v|
    options[:uuid] = v.downcase
  end
end.parse!

abort("You must specify --uuid <UUID>") if options[:uuid].nil?
abort("You must specify at least one file or glob pattern") if ARGV.empty?

uuid_regex   = /^\s*#{Regexp.escape(options[:uuid])}:/i
offset_regex = /^[0-9A-Fa-f]{6}\s{2}/

def extract_from_files(files, uuid_regex, offset_regex)
  found_any = false

  files.each do |filename|
    File.open(filename, "rb") do |file|
      in_block = false
      file.each_line do |line|
        line.force_encoding('ASCII-8BIT')

        if in_block
          if line =~ offset_regex
            print line
            found_any = true
            next
          else
            in_block = false
          end
        end

        if line =~ uuid_regex
          data_after_colon = line.split(':', 2)[1]
          print data_after_colon
          found_any = true
          in_block = true
        end
      end
    end
  rescue => e
    warn "Warning: could not process #{filename}: #{e.message}"
  end

  found_any
end
initial_files = ARGV.flat_map { |pattern| Dir.glob(pattern) }.uniq

if initial_files.empty?
  raw_match = ARGV.map { |pattern| pattern[%r{^(.*?/raw/)}] }.compact.first

  if raw_match
    base_dir = Pathname.new(raw_match).parent.parent
    fallback_files = Dir.glob(base_dir.join('**', '*.txt').to_s).uniq

    if fallback_files.empty?
      abort("No files matched your pattern(s), and no fallback .txt files found in #{base_dir}")
    else
      initial_files = fallback_files
    end
  else
    abort("No files matched your pattern(s), and no '/raw/' path detected for fallback")
  end
end

found = extract_from_files(initial_files, uuid_regex, offset_regex)

unless found
  raw_dir_prefix = ARGV.map { |pattern| pattern[%r{^(.*?/raw/)}] }.compact.first

  if raw_dir_prefix
    base_dir = Pathname.new(raw_dir_prefix).parent.parent
    fallback_files = Dir.glob(base_dir.join('**', '*').to_s).select { |f| File.file?(f) }
    extract_from_files(fallback_files, uuid_regex, offset_regex)
  else
    puts "No '/raw/' directory structure found in file paths, skipping fallback."
  end
end