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

#include "Probes.h"
#include "Config.h"

#include <iostream>


using namespace std;

Prober::Prober() {
	pthread_mutex_init(&probeBufferLock, NULL);
}

void Prober::Probe() {
	// TODO: Support multiple types of probes
	SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, CI->m_dstport, CI->m_srcport);
}

void Prober::SendSYN(
		addr dstIP, addr dstMAC,
		addr srcIP, addr srcMAC,
		int dstPort, int srcPort)
{
	pthread_mutex_lock(&probeBufferLock);
	eth_pack_hdr(probeBuffer, dstMAC.addr_eth, srcMAC.addr_eth, ETH_TYPE_IP);
	ip_pack_hdr(probeBuffer + ETH_HDR_LEN, 0, IP_HDR_LEN + TCP_HDR_LEN, 0, 0, 128, IP_PROTO_TCP, srcIP.addr_ip, dstIP.addr_ip);
	tcp_pack_hdr(probeBuffer + ETH_HDR_LEN + IP_HDR_LEN, srcPort, dstPort, 0x42, 0, TH_SYN, 4096, 0);
	ip_checksum(probeBuffer + ETH_HDR_LEN, probeBufferSize - ETH_HDR_LEN);
	pthread_mutex_unlock(&probeBufferLock);

	eth_t *eth = eth_open(CI->m_interface.c_str());
	if (eth == NULL) {
		cout << "Unable to open ethernet interface to send TCP SYN" << endl;
		return;
	}

	cout << ">> Sending SYN probe to " << addr_ntoa(&dstIP) << " / " << addr_ntoa(&dstMAC) << " from " << addr_ntoa(&srcIP) << " / " << addr_ntoa(&srcMAC) << endl;

	eth_send(eth, probeBuffer, probeBufferSize);
	eth_close(eth);
}

void Prober::SendARPReply(
		struct addr *srcMAC, struct addr *dstMAC, struct addr *srcIP, struct addr *dstIP, int opcode, struct addr *tha)
{
	// Usually tha is going to be the destination MAC, except for weird cases with gratuitous replies
	if (tha == NULL) {
		tha = dstMAC;
	}
    u_char pkt[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];

    eth_pack_hdr(pkt, dstMAC->addr_eth, srcMAC->addr_eth, ETH_TYPE_ARP);
    arp_pack_hdr_ethip(pkt + ETH_HDR_LEN, opcode, srcMAC->addr_eth,
        srcIP->addr_ip, tha->addr_eth, dstIP->addr_ip);

	eth_t *eth = eth_open(CI->m_interface.c_str());
	if (eth == NULL) {
		cout << "Unable to open ethernet interface to send TCP SYN" << endl;
		return;
	}

	if (opcode == ARP_OP_REPLY) {
		cout << ">> Sending ARP_REPLY to ";
	} else if (opcode == ARP_OP_REQUEST) {
		cout << ">> Sending ARP_REQUEST to ";
	} else {
		cout << "ERROR: Invalid ARP op code" << endl;
	}

	cout << addr_ntoa(dstIP) << " / " << addr_ntoa(dstMAC) << " from " << addr_ntoa(srcIP) << " / " << addr_ntoa(srcMAC) << " and THA of " << addr_ntoa(tha) << endl;

	eth_send(eth, pkt, ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN);
	eth_close(eth);
}
