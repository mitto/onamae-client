# -*- coding:utf-8 -*-

require 'logger'
require 'yaml'
require 'socket'
require 'openssl'
require 'open-uri'

module OnamaeDDNS
  DDNS_HOST = "ddnsclient.onamae.com"
  DDNS_PORT = 65001
  class Client
    def initialize
      config          = YAML.load_file("config.yml")
      @userid         = config["userid"]
      @password       = config["password"]
      @update_domains = config["domains"]
    end

    def logger
      @logger ||= Logger.new(STDOUT)
      @logger.level = Logger::INFO
      @logger
    end

    def create_socket
      cert_file         = "cert.pfx"
      socket            = TCPSocket.new(DDNS_HOST, DDNS_PORT)
      context           = OpenSSL::SSL::SSLContext.new()
      cert              = OpenSSL::PKCS12.new(open(cert_file), "dice")
      context.cert      = cert.certificate
      context.key       = cert.key
      socket            = OpenSSL::SSL::SSLSocket.new(socket, context)
      socket.sync_close = true
      socket
    end

    def login
      logger.info("login : start")
      command = loggin_command(@userid, @password)
      logger.debug("loggin command : #{command}")
      begin
        socket = create_socket
        socket.connect
        socket.puts(command)
        parse_receive_message(socket.gets)
        logger.info("login : finish")
        yield socket
        command = logout_command
        logger.info("logout : start")
        socket.puts(command)
        logger.info("logout : finish")
      rescue
        logger.error("failed ddns update execution!")
      ensure
        socket.close
      end
    end

    def update!
      login do |socket|
        logger.info("update : start")
        ip = fetch_global_ip
        logger.info("global ip : #{ip}")
        @update_domains.each do |domain|
          domain.each_pair do |domain_name, hosts|
            hosts ||= [""]
            logger.info("update domain : #{domain_name}")
            hosts.each do |host|
              logger.info("update hostname : #{host}")
              command = modip_command(host, domain_name, ip)
              logger.debug("update command : #{command}")
              socket.puts(command)
              socket.gets
              parse_receive_message(socket.gets)
            end
          end
        end
        logger.info("update : finish")
      end
    end

    def run
      logger.info("update onamae ddns : start")
      update!
      logger.info("update onamae ddns : end")
    end

    def loggin_command(userid, password)
      <<-EOL.gsub(/^ +/, '')
        LOGIN
        USERID:#{userid}
        PASSWORD:#{password}
        .
      EOL
    end

    def logout_command
      <<-EOL.gsub(/^ +/, '')
        LOGOUT
        .
      EOL
    end

    def modip_command(host, domain, ip)
      <<-EOL.gsub(/^ +/, '')
        MODIP
        HOSTNAME:#{host}
        DOMNAME:#{domain}
        IPV4:#{ip}
        .
      EOL
    end

    def fetch_global_ip
      begin
        open("http://mittostar.info/ip.php").read
      end
    end

    def parse_receive_message(message)
      message = message.chomp
      code = message.split.first
      case code
      when "000"
        logger.info("receive message : #{message}")
      else
        logger.error("recive message : #{message}")
        raise
      end
    end
  end
end

if $0 == __FILE__
  OnamaeDDNS::Client.new.run
end
