AM_CFLAGS = --pedantic -Wall -std=c11 -O0

bin_PROGRAMS = ncf

LDADD = -lpcap -lpthread -ldumbnet -lboost_program_options
ncf_SOURCES = FilePacketCapture.cpp \
		InterfacePacketCapture.cpp \
		PacketCapture.cpp \
		Config.cpp \
		Probes.cpp \
		helpers.cpp \
		ArpFingerprint.cpp \
		main.cpp
