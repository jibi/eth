require 'rake'
require 'rake/clean'

NAME    = 'eth'

CC      = ENV['CC'] || 'clang'
CFLAGS  = ENV['CFLAGS'].to_s + " -Wall -pedantic -g -DDEBUG=1 -Wno-c11-extensions -I ./include -I ./deps/netmap/sys `pkg-config --cflags glib-2.0`"
LDFLAGS = ENV['LDFLAGS'].to_s + " `pkg-config --libs glib-2.0`"

PARSER  = FileList['src/*.rl']
SOURCES = FileList['src/*.c'] + FileList['src/**/*c']
OBJECTS = (SOURCES.ext('o') + PARSER.ext('o')).uniq

CLEAN.include(OBJECTS).include(NAME).include(PARSER.ext('c'))

task :default => [PARSER.ext('c'), NAME]
task :deps => [:netmap]

task :netmap do
  sh "cd deps/netmap/LINUX; make clean; make"
end

file NAME => OBJECTS do
	sh "#{CC} #{LDFLAGS} #{OBJECTS} -o #{NAME}"
end

rule '.c' => '.rl' do |file|
	sh "ragel #{file.source}"
end

rule '.o' => '.c' do |file|
	sh "#{CC} #{CFLAGS} -c #{file.source} -o #{file}"
end

