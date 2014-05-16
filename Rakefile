require 'rake'
require 'rake/clean'

NAME    = 'eth'

CC      = ENV['CC'] || 'clang'
CFLAGS  = ENV['CFLAGS'].to_s + " -Wall -pedantic -g -DDEBUG -Wno-zero-length-array -Wno-gnu-zero-variadic-macro-arguments -I ./include -I ./deps/picotcp/build/include -I ./deps/netmap/sys"
LDFLAGS = ENV['LDFLAGS'].to_s

PARSER  = FileList['src/http11/*.rl']
SOURCES = FileList['src/*.c'] + FileList['src/*/*.c']
OBJECTS = (SOURCES.ext('o') + PARSER.ext('o')).uniq

CLEAN.include(OBJECTS).include(NAME).include(PARSER.ext('c'))

task :default => [PARSER.ext('c'), NAME]
task :deps => [:picotcp, :netmap]

task :picotcp do
  sh "make -C deps/picotcp clean; make -C deps/picotcp IPV6=0 NAT=0 MCAST=0 IPFILTER=0 DNS_CLIENT=0 SNTP_CLIENT=0 DHCP_CLIENT=0 DHCP_SERVER=0 HTTP_CLIENT=0 HTTP_SERVER=0 OLSR=0 SLAACV4=0 IPFRAG=0 DEBUG=0"
end

task :netmap do
  sh "cd deps/netmap/LINUX; make clean; make"
end

file NAME => OBJECTS do
	sh "#{CC} #{LDFLAGS} #{OBJECTS} deps/picotcp/build/lib/libpicotcp.a -o #{NAME}"
end

rule '.c' => '.rl' do |file|
	sh "ragel #{file.source}"
end

rule '.o' => '.c' do |file|
	sh "#{CC} #{CFLAGS} -c #{file.source} -o #{file}"
end

