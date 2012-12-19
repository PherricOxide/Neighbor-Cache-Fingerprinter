#include <iostream>
#include <dumbnet.h>
#include <cstring>
#include <sstream>

#include "InterfacePacketCapture.h"
#include "ArpFingerprint.h"
#include "Config.h"

using namespace std;
using namespace Nova;


// TOOD: Might want to move state data out of the fingerprint and into per test structs of some sort
ArpFingerprint fingerprint;

/* Buffer for our probe packets */
const int probeBufferSize = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
unsigned char probeBuffer[probeBufferSize];
pthread_mutex_t probeBufferLock;

/* This indicates that we've seen the probe packet that we sent and can wait for replies */
bool seenProbe = false;

timeval lastARPReply; /* Used to compute the time between ARP requests */

void packetCallback(unsigned char *index, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
	if (pkthdr->len < ETH_HDR_LEN)
		return;

	eth_hdr *eth = (eth_hdr*)packet;
	addr dstMac;
	addr_pack(&dstMac, ADDR_TYPE_ETH, ETH_ADDR_BITS, &eth->eth_dst, ETH_ADDR_LEN);

	/* Stuff the broadcast MAC in an addr type for comparison later */
	addr broadcastMAC;
	unsigned char broadcastBuffer[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	addr_pack(&broadcastMAC, ADDR_TYPE_ETH, ETH_ADDR_BITS, broadcastBuffer, ETH_ADDR_LEN);

	if (ntohs(eth->eth_type) == ETH_TYPE_ARP)
	{
		/* We ignore everything before our probe has been sent */
		if (!seenProbe)
			return;

		if (pkthdr->len < ETH_HDR_LEN + ARP_HDR_LEN)
			return;

		arp_hdr *arp = (arp_hdr*)(packet + ETH_HDR_LEN);
		if (ntohs(arp->ar_op) == ARP_OP_REQUEST)
		{
			if (pkthdr->len < ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN)
				return;

			arp_ethip *arpRequest = (arp_ethip*)(packet + ETH_HDR_LEN + ARP_HDR_LEN);
			addr addr;
			addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, arpRequest->ar_tpa, IP_ADDR_LEN);
			cout << "Got request for IP " << addr_ntoa(&addr) << endl;

			if (addr_cmp(&addr, &CI->m_srcip) == 0)
			{
				if (addr_cmp(&dstMac, &CI->m_srcmac) == 0)
				{
					fingerprint.unicastRequest = true;
				}
				else if (addr_cmp(&dstMac, &broadcastMAC) == 0) {
					fingerprint.unicastRequest = false;
				}
				else
				{
					cout << "WARNING: Got an ARP packet that was neither to the broadcast MAC or our probe MAC. This is unusual." << endl;
				}

				fingerprint.arpRequests++;
				if (fingerprint.arpRequests > 1 && fingerprint.arpRequests < MAX_RECORDED_REPLIES)
				{
					int diff = 0;
					diff += 1000000*(pkthdr->ts.tv_sec  - lastARPReply.tv_sec);
					diff += pkthdr->ts.tv_usec - lastARPReply.tv_usec;
					fingerprint.timeBetweenRequests[fingerprint.arpRequests - 2] = diff;

					/* Compute the average time between requests */
					double sum = 0;
					for (int i = 0; i < (fingerprint.arpRequests - 1); i++)
						sum += fingerprint.timeBetweenRequests[i];
					fingerprint.averageTimeBetweenRequests = sum / (fingerprint.arpRequests - 1);


					cout << fingerprint.toString() << endl << endl;
				}
				lastARPReply = pkthdr->ts;
			}
		}
	}
	else if (ntohs(eth->eth_type) == ETH_TYPE_IP)
	{
		if (pkthdr->len < ETH_HDR_LEN + IP_HDR_LEN)
			return;

		ip_hdr *ip = (ip_hdr*)(packet + ETH_HDR_LEN);

		/* Check if our own probe packet went over the interface */
		if (!seenProbe)
		{
			if (pkthdr->len != probeBufferSize)
				return;

			for (int i = 0; i < pkthdr->len; i++)
			{
				if (packet[i] != probeBuffer[i])
				{
					return;
				}
			}

			seenProbe = true;
			cout << "Saw our probe packet" << endl;
		}
		else
		{
			addr dstIp;
			addr_pack(&dstIp, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);

			if (addr_cmp(&dstIp, &CI->m_dstip) == 0 && addr_cmp(&dstMac, &CI->m_dstmac))
			{
				fingerprint.sawResponse = true;
				if (fingerprint.arpRequests == 0)
					fingerprint.replyBeforeARP = true;
				else
					fingerprint.replyBeforeARP = false;
			}

		}
	}
}

void SendSYN(
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
	if (eth == NULL)
	{
		cout << "Unable to open ethernet interface to send TCP SYN" << endl;
		return;
	}

	eth_send(eth, probeBuffer, probeBufferSize);
	eth_close(eth);
}

int main(int argc, char ** argv)
{
	Config::Inst()->LoadArgs(argv, argc);
	

	pthread_mutex_init(&probeBufferLock, NULL);


	InterfacePacketCapture *capture = new InterfacePacketCapture(CI->m_interface);
	capture->Init();
	capture->SetPacketCb(&packetCallback);

	stringstream ss;
	ss << "arp or (dst host " << CI->m_srcipString << ")";
	capture->SetFilter(ss.str());

	capture->StartCapture();
	sleep(1);

	SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, 42, 54629);

	// TODO: Make a timeout for the test. Shouldn't monitor forever.
	while (1)
	{
		sleep(9999);
	}


	return 0;
}


