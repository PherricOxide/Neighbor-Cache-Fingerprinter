//============================================================================
// Copyright   : David Clark (PherricOxide) 2012-2013
//	 The Neighbor Cache Fingerprinter is free software:
//   you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.
//
//   This software is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this software.  If not, see <http://www.gnu.org/licenses/>.
//============================================================================

#include <dnet.h>
#include <pthread.h>
#include <pcap.h>
#include <string>

enum ProbeType {
	PROBE_TYPE_TCP,
	PROBE_TYPE_ICMP,
	PROBE_TYPE_UDP
};

class Prober {
public:
	/* Buffer for our probe packets */
private:
	static const int probeBufferSize = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
	uint lastProbeSize;
	unsigned char probeBuffer[probeBufferSize];
	pthread_mutex_t probeBufferLock;

	int SendTCPProbe(
				addr dstIP, addr dstMAC,
				addr srcIP, addr srcMAC,
				int dstPort, int srcPort);

	int SendUDPProbe(
			addr dstIP, addr dstMAC,
			addr srcIP, addr srcMAC,
			int dstPort, int srcPort);

	int SendICMPProbe(addr dstIP, addr dstMAC,addr srcIP, addr srcMAC);


public:

	Prober();
	void SetProbeType(std::string type);

	void Probe();

	void SendARPReply(struct addr *srcMAC, struct addr *dstMAC, struct addr *srcIP, struct addr *dstIP, int opcode = ARP_OP_REPLY, struct addr *tha = NULL);


	bool isThisLastProbePacket(const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
	bool isThisProbeReply(const struct pcap_pkthdr *pkthdr, const unsigned char *packet);


	ProbeType probeType;
	uint16_t lastICMPSequenceNumber;
	uint16_t lastICMPIdNumber;
	uint32_t lastTCPSequenceNumber;
};
