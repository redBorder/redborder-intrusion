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

require 'json'
require 'socket'
require 'net/http'
require "getopt/std"
require 'fileutils'
require 'base64'
require 'time'
require 'digest/sha1'
require 'openssl'
require 'net/https'

class ChefAPI

  # Public: Gets/Sets the http object.
  attr_accessor :http

  # Public: Gets/Sets the String path for the HTTP request.
  attr_accessor :path

  # Public: Gets/Sets the String client_name containing the Chef client name.
  attr_accessor :client_name

  # Public: Gets/Sets the String key_file that is path to the Chef client PEM file.
  attr_accessor :key_file

  # Public: Initialize a Chef API call.
  #
  # opts - A Hash containing the settings desired for the HTTP session and auth.
  #        :server       - The String server that is the Chef server name (required).
  #        :port         - The String port for the Chef server (default: 443).
  #        :use_ssl      - The Boolean use_ssl to use Net::HTTP SSL
  #                        functionality or not (default: true).
  #        :ssl_insecure - The Boolean ssl_insecure to skip strict SSL cert
  #                        checking (default: OpenSSL::SSL::VERIFY_PEER).
  #        :client_name  - The String client_name that is the name of the Chef
  #                        client (required).
  #        :key_file     - The String key_file that is the path to the Chef client
  #                        PEM file (required).
  def initialize(opts={})
    server            = opts[:server]
    port              = opts.fetch(:port, 443)
    use_ssl           = opts.fetch(:use_ssl, true)
    ssl_insecure      = opts[:ssl_insecure] ? OpenSSL::SSL::VERIFY_NONE : OpenSSL::SSL::VERIFY_PEER
    @client_name      = opts[:client_name]
    @key_file         = opts[:key_file]

    @http             = Net::HTTP.new(server, port)
    @http.use_ssl     = use_ssl
    @http.verify_mode = ssl_insecure
  end

  # Public: Make the actual GET request to the Chef server.
  #
  # req_path - A String containing the server path you want to send with your
  #            GET request (required).
  #
  # Examples
  #
  #   get_request('/environments/_default/nodes')
  #   # => ["server1.com","server2.com","server3.com"]
  #
  # Returns different Object type depending on request.
  def get_request(req_path)
    @path = req_path

    begin
      request  = Net::HTTP::Get.new(path, headers)
      response = http.request(request)

      response.body
    rescue OpenSSL::SSL::SSLError => e
      raise "SSL error: #{e.message}."
    end
  end

  private

  # Private: Encode a String with SHA1.digest and then Base64.encode64 it.
  #
  # string - The String you want to encode.
  #
  # Examples
  #
  #   encode('hello')
  #   # => "qvTGHdzF6KLavt4PO0gs2a6pQ00="
  #
  # Returns the hashed String.
  def encode(string)
    ::Base64.encode64(Digest::SHA1.digest(string)).chomp
  end

  # Private: Forms the HTTP headers required to authenticate and query data
  # via Chef's REST API.
  #
  # Examples
  #
  #   headers
  #   # => {
  #     "Accept"                => "application/json",
  #     "X-Ops-Sign"            => "version=1.0",
  #     "X-Ops-Userid"          => "client-name",
  #     "X-Ops-Timestamp"       => "2012-07-27T20:09:25Z",
  #     "X-Ops-Content-Hash"    => "JJKXjxksmsKXM=",
  #     "X-Ops-Authorization-1" => "JFKXjkmdkDMKCMDKd+",
  #     "X-Ops-Authorization-2" => "JFJXjxjJXXJ/FFjxjd",
  #     "X-Ops-Authorization-3" => "FFJfXffffhhJjxFJff",
  #     "X-Ops-Authorization-4" => "Fjxaaj2drg5wcZ8I7U",
  #     "X-Ops-Authorization-5" => "ffjXeiiiaHskkflllA",
  #     "X-Ops-Authorization-6" => "FjxJfjkskqkfjghAjQ=="
  #   }
  #
  # Returns a Hash with the necessary headers.
  def headers
    # remove parameters from the path
    _path=path.split('?').first

    body      = ""
    timestamp = Time.now.utc.iso8601
    key       = OpenSSL::PKey::RSA.new(File.read(key_file))
    canonical = "Method:GET\nHashed Path:#{encode(_path)}\nX-Ops-Content-Hash:#{encode(body)}\nX-Ops-Timestamp:#{timestamp}\nX-Ops-UserId:#{client_name}"

    header_hash = {
      'Accept'             => 'application/json',
      'X-Ops-Sign'         => 'version=1.0',
      'X-Ops-Userid'       => client_name,
      'X-Ops-Timestamp'    => timestamp,
      'X-Ops-Content-Hash' => encode(body)
    }

    signature = Base64.encode64(key.private_encrypt(canonical))
    signature_lines = signature.split(/\n/)
    signature_lines.each_index do |idx|
      key = "X-Ops-Authorization-#{idx + 1}"
      header_hash[key] = signature_lines[idx]
    end

    header_hash
  end

end

CLIENTPEM    = "/etc/chef/client.pem"
QUIET        = 0
TFLITE_MAGIC = [0x1c, 0x00, 0x00, 0x00, 0x54, 0x46, 0x4c, 0x33]

@reload_snort = 0
@reload_snort_ips = 0
@restart_snort = 0

ret=0

RES_COL     = 76

print "Execution: rb_get_sensor_rules.rb"
ARGV.each do |a|
  print " #{a}"
end
print "\n"

opt = Getopt::Std.getopts("hg:b:i:d:n:srfw")
if opt["h"] or opt["g"].nil? 
  printf "rb_get_sensor_rules.rb [-h] [-f] -g group_id -b binding_id -d dbversion_id\n"
  printf "    -h                -> print this help\n"
  printf "    -g group_id       -> Group Id (numeric or full instance name)\n"
  printf "    -b binding_id     -> Binding Id\n"
  printf "    -d dbversion_ids  -> Rule database version IDs\n"
  printf "    -s                -> Save this command into the proper rb_get_sensor_rules.sh file\n"
  printf "    -r                -> Include reputation list\n"
  printf "    -w                -> Don't rollback in case of errors\n"
  exit 1
end

@group_id_str  = opt["g"]
savecmd        = !opt["s"].nil?
reputation     = !opt["r"].nil?
rollback       = opt["w"].nil?
binding_ids    = []

if opt["b"].is_a? Array
  binding_ids += opt["b"]
elsif !opt["b"].nil?
  binding_ids << opt["b"]
end

cdomain = File.read('/etc/redborder/cdomain').strip rescue 'redborder.cluster'
@weburl = "webui.#{cdomain}"
@client_name = File.read('/etc/chef/nodename').strip
@client_id   = @client_name.split('-').last

# NEW LOGIC: Determine instance_dir and numeric_group_id
instance_dir = "/etc/snort/#{@group_id_str}"
@numeric_group_id = @group_id_str.split('_').first

if !Dir.exist?(instance_dir) or !File.exist?("#{instance_dir}/env")
  print "ERROR: The group id #{@group_id_str} doesn't exist or has no CPUs assigned\n"
  exit 1
end

@v_snortml_dir          = "#{instance_dir}/ml_models"
@v_iplist_dir           = "#{instance_dir}/iplists"
@v_iplistname           = "iplist_script.sh"
@v_iplist               = "#{@v_iplist_dir}/#{@v_iplistname}"
@v_iplist_zone          = "#{@v_iplist_dir}/zone.info"
@v_geoip_dir            = "#{instance_dir}/geoips"
@v_geoipname            = "rbgeoip"
@v_geoip                = "#{@v_geoip_dir}/#{@v_geoipname}"
@v_unicode_mapname      = "unicode.map"
@v_unicode_map          = "#{instance_dir}/#{@v_unicode_mapname}"
@v_snortml_rule         = "#{instance_dir}/ml.rules"

@chef=ChefAPI.new(
  server: @weburl,
  use_ssl: true,
  ssl_insecure: true,
  client_name: @client_name,
  key_file: "/etc/chef/client.pem"
)

def print_ok(text_length=76)
  printf("%#{RES_COL - text_length}s", "[  OK  ]")
  puts ""
end

def print_fail(text_length=76)
  print sprintf("%#{RES_COL - text_length}s", "[  FAILED  ]")
  puts ""
end

def get_rules(remote_name, snortrules, binding_id)
  snortrulestmp = "#{snortrules}.tmp" 
  print "Downloading #{remote_name} "
  print_length = "Downloading #{remote_name} ".length

  File.delete(snortrulestmp) if File.exist?(snortrulestmp)

  result = @chef.get_request("/sensors/#{@client_id}/#{remote_name}?group_id=#{@numeric_group_id}&binding_id=#{binding_id}")
  if result and !result.start_with?('<!DOCTYPE html>')
    File.open(snortrulestmp, 'w') { |f| f.write(result) }

    unless File.zero?(@v_snortml_rule)
      File.open(snortrulestmp, 'a') do |f|
        f.write(File.read(@v_snortml_rule))
      end
    end

    v_md5sum_tmp  = Digest::MD5.hexdigest(File.read(snortrulestmp))
    v_md5sum      = File.exist?(snortrules) ? Digest::MD5.hexdigest(File.read(snortrules)) : ""

    if v_md5sum != v_md5sum_tmp
      File.zero?(@v_iplist_zone) ? @reload_snort = 1 : @restart_snort = 1
    else
      print "(not modified) "
      print_length += "(not modified) ".length
      File.delete(snortrulestmp) if File.exist?(snortrulestmp)
    end

    print_ok(print_length)
    return true
  else  
    print_fail(print_length)
    return false
  end
end

def get_classifications(v_rulefile)
  print "Downloading classifications "
  print_length = "Downloading classifications ".length

  v_classifications = File.join(File.dirname(v_rulefile), "classification.config")
  File.delete "#{v_classifications}.tmp" if File.exist?("#{v_classifications}.tmp")

  result = @chef.get_request("/sensors/#{@client_id}/classifications.txt?group_id=#{@numeric_group_id}")

  if result and !result.start_with?('<!DOCTYPE html>')
    File.open("#{v_classifications}.tmp", 'w') {|f| f.write(result)}
    v_md5sum_tmp    = Digest::MD5.hexdigest(File.read("#{v_classifications}.tmp"))
    v_md5sum        = File.exists?(v_classifications) ? Digest::MD5.hexdigest(File.read(v_classifications)) : ""

    if v_md5sum != v_md5sum_tmp
      File.zero?(@v_iplist_zone) ? @reload_snort = 1 : @restart_snort = 1
    else
      print "(not modified) "
      print_length += "(not modified) ".length
      File.delete("#{v_classifications}.tmp") if File.exist?("#{v_classifications}.tmp")
    end

    print_ok(print_length)
    return true
  else
    print_fail(print_length)
    return false
  end
end

def get_thresholds(binding_id, v_rulefile)
  print "Downloading thresholds "
  print_length = "Downloading thresholds ".length

  v_threshold = File.join(File.dirname(v_rulefile), "events.lua")
  File.delete "#{v_threshold}.tmp" if File.exist?("#{v_threshold}.tmp")

  result = @chef.get_request("/sensors/#{@client_id}/thresholds.txt?group_id=#{@numeric_group_id}&binding_id=#{binding_id}")

  if result and !result.start_with?('<!DOCTYPE html>')
    content_to_write = result.gsub(/^#/, '--')
    File.open("#{v_threshold}.tmp", 'w') {|f| f.write(content_to_write)}
    
    v_md5sum_tmp    = Digest::MD5.hexdigest(File.read("#{v_threshold}.tmp"))
    v_md5sum        = File.exists?(v_threshold) ? Digest::MD5.hexdigest(File.read(v_threshold)) : ""

    if v_md5sum != v_md5sum_tmp
      File.zero?(@v_iplist_zone) ? @reload_snort = 1 : @restart_snort = 1
    else
      print "(not modified) "
      print_length += "(not modified) ".length
      File.delete("#{v_threshold}.tmp") if File.exist?("#{v_threshold}.tmp")
    end

    print_ok(print_length)
    return true
  else
    print_fail(print_length)
    return false
  end
end

def get_snortml_model
  puts "Downloading SnortML model..."
  print_length = "Downloading SnortML model...".length

  model = "snort.model"
  file_path = File.join(@v_snortml_dir, model)
  tmp_file_path = "#{file_path}.tmp"

  FileUtils.mkdir_p(File.dirname(file_path))
  File.delete(tmp_file_path) if File.exist?(tmp_file_path)

  result = @chef.get_request("/sensors/#{@client_id}/snortml_model")

  if result and !result.start_with?('<!DOCTYPE html>')
    File.open(tmp_file_path, 'wb') { |f| f.write(result) }

    if File.zero?(tmp_file_path)
      File.delete(tmp_file_path)
      print " (empty file ignored)"
      print_fail(print_length)
      return false
    end

    unless tensorflow_lite_model?(tmp_file_path)
      File.delete(tmp_file_path)
      print " (invalid TensorFlow Lite model ignored)"
      print_fail(print_length)
      return false
    end

    tmp_md5 = Digest::MD5.hexdigest(File.read(tmp_file_path))
    existing_md5 = File.exist?(file_path) ? Digest::MD5.hexdigest(File.read(file_path)) : ""

    if tmp_md5 != existing_md5
      File.rename(tmp_file_path, file_path)
      puts " (updated)"
    else
      File.delete(tmp_file_path)
      print " (not modified)"
    end

    print_ok(print_length)
    return true
  else
    print_fail(print_length)
    return false
  end
end

def get_iplist_files
  print "Downloading iplist files "
  print_length = "Downloading iplist files ".length

  File.delete "#{@v_iplist}.tmp" if File.exist?("#{@v_iplist}.tmp")

  result = @chef.get_request("/sensors/#{@client_id}/iplist_v4.txt?group_id=#{@numeric_group_id}")

  if result and !result.start_with?('<!DOCTYPE html>')
    FileUtils.mkdir_p @v_iplist_dir
    File.open("#{@v_iplist}.tmp", File::CREAT|File::TRUNC|File::RDWR, 0755){|f| f.write(result)}
    v_md5sum_tmp    = Digest::MD5.hexdigest(File.read("#{@v_iplist}.tmp"))
    v_md5sum        = File.exists?(@v_iplist) ? Digest::MD5.hexdigest(File.read(@v_iplist)) : ""

    if v_md5sum != v_md5sum_tmp
      system("rm -f #{@v_iplist}; mv #{@v_iplist}.tmp #{@v_iplist}; sh #{@v_iplist}")
      if File.zero?("#{@v_iplist_zone}")
        @reload_snort = 1
      else
        @restart_snort = 1
        @reload_snort_ips = 1
      end
    else
      print "(not modified) "
      print_length += "(not modified) ".length
      File.delete("#{@v_iplist}.tmp") if File.exist?("#{@v_iplist}.tmp")
    end

    print_ok(print_length)
    return true
  else
    print_fail(print_length)
    return false
  end
end

def get_geoip_files
  print "Downloading geoip files "
  print_length = "Downloading geoip files ".length

  File.delete "#{@v_geoip}.tmp" if File.exist?("#{@v_geoip}.tmp")

  result = @chef.get_request("/sensors/#{@client_id}/geoip_v4.txt?group_id=#{@numeric_group_id}")

  if result and !result.start_with?('<!DOCTYPE html>')
    FileUtils.mkdir_p @v_geoip_dir
    File.open("#{@v_geoip}.tmp", File::CREAT|File::TRUNC|File::RDWR, 0755){|f| f.write(result)}
    v_md5sum_tmp    = Digest::MD5.hexdigest(File.read("#{@v_geoip}.tmp"))
    v_md5sum        = File.exists?(@v_geoip) ? Digest::MD5.hexdigest(File.read(@v_geoip)) : ""

    if v_md5sum != v_md5sum_tmp
      system("rm -f #{@v_geoip}; mv #{@v_geoip}.tmp #{@v_geoip}; sh #{@v_geoip}")
      File.zero?(@v_iplist_zone) ? @reload_snort = 1 : @restart_snort = 1
    else
      print "(not modified) "
      print_length += "(not modified) ".length
      File.delete("#{@v_geoip}.tmp") if File.exist?("#{@v_geoip}.tmp")
    end

    print_ok(print_length)
    return true
  else
    print_fail(print_length)
    return false
  end
end

def find(dir, filename="*.*\"")
  Dir[ File.join(dir.split(/\\/), filename) ]
end

def copy_backup( backup_dir, datestr, temp_file_path, final_file_path, filename, backups )
  if File.exist?(temp_file_path)
    if File.exist?(final_file_path)
      print "Backed to #{filename}-#{datestr}\n"
      backups << "#{backup_dir}/#{filename}-#{datestr}"
      FileUtils.copy(final_file_path, "#{backup_dir}/#{filename}-#{datestr}")
    end
    File.rename(temp_file_path, final_file_path)

    files = Dir.entries(backup_dir).select {|x| x =~ /^#{filename}-/}.sort
    if files.size > BACKUPCOUNT
      files.first(files.size-BACKUPCOUNT).each do |f|
        if File.exist?("#{backup_dir}/#{f}")
          print "Removed backup at #{backup_dir}/#{f}\n"
          File.delete("#{backup_dir}/#{f}") 
        end
      end
    end
  end
end

if !File.exists?(CLIENTPEM)
  puts "The sensor is not registered!"
  exit
end

BACKUPCOUNT = 5
backups = []
datestr = Time.now.strftime("%Y%m%d%H%M%S")
backup_dir = "#{instance_dir}/backups"
tmp_backup_tgz = "/tmp/rb_get_sensor_rules-#{File.basename(instance_dir)}-#{datestr}-#{rand(1000)}.tgz"

FileUtils.mkdir_p backup_dir
system("cd #{instance_dir}; tar czf #{tmp_backup_tgz} . 2>/dev/null")

if reputation
  print "Reputation:\n"
  get_iplist_files
  get_geoip_files
end

if @reload_snort == 1 or @restart_snort == 1
  copy_backup(backup_dir, datestr, "#{@v_iplist}.tmp", @v_iplist, @v_iplistname, backups)
  copy_backup(backup_dir, datestr, "#{@v_geoip}.tmp", @v_geoip, @v_geoipname,  backups)
end

File.delete "#{instance_dir}/unicode.map.tmp" if File.exist?("#{instance_dir}/unicode.map.tmp")

binding_ids.each do |binding_id|
  binding_info = binding_id.to_s.split(',')
  binding_info.each do |binfo|
    binding_id_val = nil
    dbversion_ids = []
    bind_match = /^([^:]+):(.+)$/.match(binfo.strip)

    if bind_match.nil? 
      dbversion_ids = opt["d"].to_s.split(',')
      binding_id_val = binfo.to_i
    else
      binding_id_val = bind_match[1].to_i
      dbversion_ids = bind_match[2].to_s.split(',')
    end

    if binding_id_val.nil? or binding_id_val < 0
      print "Error: binding id not found or it is not valid\n"
      next
    elsif dbversion_ids.empty? or dbversion_ids.first.empty?
      print "Error: dbversion id not found or it is not valid\n"
      next
    end

    v_rulefilename         = "snort.rules"
    v_rulefile             = "#{instance_dir}/#{v_rulefilename}"
    v_classificationsname  = "classification.config"
    v_thresholdname        = "events.lua"
    v_cmdfile              = "#{instance_dir}/rb_get_sensor_rules.sh"
    
    dbversion_ids.each do |dbid|
      get_rules("active_rules.txt", v_rulefile, binding_id_val)
      get_classifications(v_rulefile)
      get_snortml_model
      get_thresholds(binding_id_val, v_rulefile)

      if @reload_snort == 1 or @restart_snort == 1
        datestr = Time.now.strftime("%Y%m%d%H%M%S")
        v_classifications      = "#{instance_dir}/#{v_classificationsname}"
        v_threshold            = "#{instance_dir}/#{v_thresholdname}"
        copy_backup(backup_dir, datestr, "#{v_rulefile}.tmp", v_rulefile, v_rulefilename, backups)
        copy_backup(backup_dir, datestr, "#{v_classifications}.tmp", v_classifications, v_classificationsname, backups)
        copy_backup(backup_dir, datestr, "#{v_threshold}.tmp", v_threshold, v_thresholdname, backups)
      end
    end

    File.delete "#{v_rulefile}.tmp" if File.exist?("#{v_rulefile}.tmp")
    v_classifications      = "#{instance_dir}/#{v_classificationsname}"
    File.delete "#{v_classifications}.tmp" if File.exist?("#{v_classifications}.tmp")
    v_threshold            = "#{instance_dir}/#{v_thresholdname}"
    File.delete "#{v_threshold}.tmp" if File.exist?("#{v_threshold}.tmp")

    if savecmd and @numeric_group_id and !binding_id_val.nil? and !dbversion_ids.empty?
      begin
        file = File.open(v_cmdfile, "w")
        file.write("#!/bin/bash\n\n") 
        file.write("/usr/lib/redborder/bin/rb_get_sensor_rules.rb -f -r -g '#{@group_id_str}' -b '#{binding_id_val}' -d '#{dbversion_ids.join(",")}'\n")
      rescue IOError => e
        print "Error saving #{file}"
      ensure
        file.close unless file == nil
      end
    end

    if @reload_snort == 1 or @restart_snort == 1
      v_classifications      = "#{instance_dir}/#{v_classificationsname}"
      v_rulefile             = "#{instance_dir}/#{v_rulefilename}"
      output = `/usr/lib/redborder/scripts/rb_remap_intrusion_rules.rb --no-color #{v_classifications} #{v_rulefile}`
      print output
      
      snort_config_file = "#{instance_dir}/config.lua"
      verify_output = `snort -c #{snort_config_file} -T 2>&1`
      if $?.success?
        if savecmd
          system("systemctl reload snort3@#{File.basename(instance_dir)}") if @reload_snort == 1
          print "Reloading snort #{File.basename(instance_dir)}" if @reload_snort == 1
          system("systemctl restart snort3@#{File.basename(instance_dir)}") if @restart_snort == 1
          print "Restarting snort #{File.basename(instance_dir)}" if @restart_snort == 1
        else
          system("systemctl reload snort3@#{File.basename(instance_dir)}") if @reload_snort == 1
          print "Reloading snort #{File.basename(instance_dir)}" if @reload_snort == 1
          system("systemctl restart snort3@#{File.basename(instance_dir)}") if @restart_snort == 1
          print "Restarting snort #{File.basename(instance_dir)}" if @restart_snort == 1
        end
        if @reload_snort_ips == 1
          sleep 15 
          text_return = `/usr/lib/redborder/bin/rb_snort_iplist #{File.basename(instance_dir)}`
          if text_return.match(/\A(ERROR: |Failed to read the response)/) and Dir.glob("#{instance_dir}/iplists/*.[w|b]lf").any?
            print "The IP/Network reputation policy has not been applied. Try later and ensure that all segments is in non-bypass mode."
          end
          sleep 15
        end
      elsif rollback
        puts "--- Detailed Snort Configuration Check Output ---"
        puts verify_output
        print "\n"
        print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        print "ERROR: configuration has errors and SNORT will not be reloaded. Rollback!! \n"
        ret=1
        if File.exists?(tmp_backup_tgz)
          backups.each do |x|
            File.delete(x) if File.exist?(x)
          end
          system("cd #{instance_dir}; tar xzf #{tmp_backup_tgz} . 2>/dev/null")
        end
      end
    end
  end
end

exit ret

## vim:ts=4:sw=4:expandtab:ai:nowrap:formatoptions=croqln:
