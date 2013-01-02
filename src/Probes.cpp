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
#include "Lock.h"
#include "helpers.h"

#include <iostream>


using namespace std;
using namespace Nova;

Prober::Prober() {
	pthread_mutex_init(&probeBufferLock, NULL);
	lastICMPSequenceNumber = 0;
	lastICMPIdNumber = 0;
	probeType = PROBE_TYPE_TCP;
}

void Prober::SetProbeType(string type) {
	if (type == "ICMP") {
		probeType = PROBE_TYPE_ICMP;
	} else if (type == "TCP") {
		probeType = PROBE_TYPE_TCP;
	} else {
		cout << "Invalid probe type '" << CI->m_probeType << "'" << endl;
		exit(1);
	}
}

void Prober::Probe() {
	// TODO: Support multiple types of probes
	if (probeType == PROBE_TYPE_TCP) {
		lastProbeSize = SendTCPProbe(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_inputSrcMac, CI->m_dstport, CI->m_srcport);
	} else if (probeType == PROBE_TYPE_ICMP) {
		lastProbeSize = SendICMPProbe(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_inputSrcMac);
	}
}

int Prober::SendTCPProbe(
		addr dstIP, addr dstMAC,
		addr srcIP, addr srcMAC,
		int dstPort, int srcPort)
{
	pthread_mutex_lock(&probeBufferLock);
	lastTCPSequenceNumber = 0x42; // This should maybe be random
	eth_pack_hdr(probeBuffer, dstMAC.addr_eth, srcMAC.addr_eth, ETH_TYPE_IP);
	ip_pack_hdr(probeBuffer + ETH_HDR_LEN, 0, IP_HDR_LEN + TCP_HDR_LEN, 0, 0, 128, IP_PROTO_TCP, srcIP.addr_ip, dstIP.addr_ip);
	tcp_pack_hdr(probeBuffer + ETH_HDR_LEN + IP_HDR_LEN, srcPort, dstPort, lastTCPSequenceNumber, 0, TH_SYN, 4096, 0);
	ip_checksum(probeBuffer + ETH_HDR_LEN, IP_HDR_LEN + TCP_HDR_LEN);
	pthread_mutex_unlock(&probeBufferLock);

	eth_t *eth = eth_open(CI->m_interface.c_str());
	if (eth == NULL) {
		cout << "Unable to open ethernet interface to send TCP SYN" << endl;
		return 0;
	}

	cout << ">> Sending SYN probe to " << addr_ntoa(&dstIP) << " / " << addr_ntoa(&dstMAC) << " from " << addr_ntoa(&srcIP) << " / " << addr_ntoa(&srcMAC) << endl;

	eth_send(eth, probeBuffer, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
	eth_close(eth);

	return ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
}

int Prober::SendICMPProbe(addr dstIP, addr dstMAC,addr srcIP, addr srcMAC) {
	pthread_mutex_lock(&probeBufferLock);
	lastICMPSequenceNumber++;
	lastICMPIdNumber = 42; // Should be probably be random, but doesn't really matter
	char payload;
	eth_pack_hdr(probeBuffer, dstMAC.addr_eth, srcMAC.addr_eth, ETH_TYPE_IP);
	ip_pack_hdr(probeBuffer + ETH_HDR_LEN, 0, IP_HDR_LEN + ICMP_LEN_MIN, 0, 0, 128, IP_PROTO_ICMP, srcIP.addr_ip, dstIP.addr_ip);
	icmp_pack_hdr_echo(probeBuffer + ETH_HDR_LEN + IP_HDR_LEN, ICMP_ECHO, ICMP_CODE_NONE,lastICMPIdNumber,lastICMPSequenceNumber, &payload,0);
	ip_checksum(probeBuffer + ETH_HDR_LEN, IP_HDR_LEN + ICMP_LEN_MIN);
	pthread_mutex_unlock(&probeBufferLock);

	eth_t *eth = eth_open(CI->m_interface.c_str());
	if (eth == NULL) {
		cout << "Unable to open ethernet interface to send TCP SYN" << endl;
		return 0;
	}

	cout << ">> Sending ICMP probe to " << addr_ntoa(&dstIP) << " / " << addr_ntoa(&dstMAC) << " from " << addr_ntoa(&srcIP) << " / " << addr_ntoa(&srcMAC) << endl;

	eth_send(eth, probeBuffer, ETH_HDR_LEN + IP_HDR_LEN + ICMP_LEN_MIN);
	eth_close(eth);

	return ETH_HDR_LEN + IP_HDR_LEN + ICMP_LEN_MIN;

}

bool Prober::isThisProbeReply(const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
	// The callback function already did checking to make sure this is an IP packet
	ip_hdr *ip = (ip_hdr*)(packet + ETH_HDR_LEN);

	addr dstIp, srcIp;
	addr_pack_ip(&dstIp, (uint8_t*)&ip->ip_dst);
	addr_pack_ip(&srcIp, (uint8_t*)&ip->ip_src);

	int ipByteLength = ip->ip_hl;
	ipByteLength = ipByteLength*4;

	// Is it from our target?
	if (addr_cmp(&srcIp, &CI->m_dstip) != 0)
		return false;

	// Is it a reply to our IP?
	if (addr_cmp(&dstIp, &CI->m_srcip) != 0)
		return false;

	if (probeType == PROBE_TYPE_TCP) {
		if (ip->ip_p != IP_PROTO_TCP)
			return false;

		tcp_hdr *tcp = (tcp_hdr*)(packet + ETH_HDR_LEN + ipByteLength);

		// We're looking for a SYN/ACK or a RST/ACK
		if (!(tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_RST))
			return false;

		if (!(tcp->th_flags & TH_ACK))
			return false;

		if (ntohl(tcp->th_ack) != (lastTCPSequenceNumber + 1))
			return false;

	} else if (probeType == PROBE_TYPE_ICMP) {
		if (ip->ip_p != IP_PROTO_ICMP)
			return false;

		if (pkthdr->len < ETH_HDR_LEN + IP_HDR_LEN + ICMP_LEN_MIN)
			return false;

		icmp_hdr *icmp = (icmp_hdr*)(packet + ETH_HDR_LEN + ipByteLength);

		if (icmp->icmp_type != ICMP_ECHOREPLY)
			return false;


		icmp_msg_echo *echoReply = (icmp_msg_echo*)(packet + ETH_HDR_LEN + ipByteLength + ICMP_HDR_LEN);

		if (ntohs(echoReply->icmp_id) != lastICMPIdNumber)
			return false;

		if (ntohs(echoReply->icmp_seq) != lastICMPSequenceNumber)
			return false;
	}

	return true;
}

bool Prober::isThisLastProbePacket(const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
	Lock(&this->probeBufferLock);
	if (pkthdr->len != lastProbeSize)
		return false;

	for (uint i = 0; i < pkthdr->len; i++) {
		if (packet[i] != probeBuffer[i])
			return false;
	}

	return true;
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
