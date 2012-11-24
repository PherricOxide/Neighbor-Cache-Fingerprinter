AM_CFLAGS = --pedantic -Wall -std=c11 -O0

bin_PROGRAMS = ncf

LDADD = -lpcap -lpthread -ldumbnet
ncf_SOURCES = FilePacketCapture.cpp \
		InterfacePacketCapture.cpp \
		PacketCapture.cpp \
		main.cpp
