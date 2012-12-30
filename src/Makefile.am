AM_CFLAGS = --pedantic -Wall -std=c11 -O0

## TODO Move ncf up a folder (doing so with automake confuses me, will look into it later)
bin_PROGRAMS = neighbor-fingerprint

neighbor_fingerprint_LDADD = -lpcap -lpthread -ldumbnet -lboost_program_options

SOURCES = FilePacketCapture.cpp \
		InterfacePacketCapture.cpp \
		PacketCapture.cpp \
		Config.cpp \
		Probes.cpp \
		helpers.cpp \
		ArpFingerprint.cpp \
		Fingerprinter.cpp

neighbor_fingerprint_SOURCES = $(SOURCES) main.cpp

## Unit tests
check_PROGRAMS = test

test_SOURCES  = $(SOURCES) TEST.cc
test_LDADD    = $(neighbor_fingerprint_LDADD) -lgtest

TESTS = test
