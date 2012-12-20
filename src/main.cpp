#include <iostream>
#include <dumbnet.h>
#include <cstring>
#include <sstream>

#include "InterfacePacketCapture.h"
#include "ArpFingerprint.h"
#include "Config.h"
#include "Probes.h"

using namespace std;
using namespace Nova;


// TOOD: Might want to move state data out of the fingerprint and into per test structs of some sort
ArpFingerprint fingerprint;


/* This indicates that we've seen the probe packet that we sent and can wait for replies */
bool seenProbe = false;

Prober prober;

timeval lastARPReply; /* Used to compute the time between ARP requests */

void packetCallback(unsigned char *index, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
	if (pkthdr->len < ETH_HDR_LEN)
		return;

	eth_hdr *eth = (eth_hdr*)packet;
	addr dstMac;
	addr_pack(&dstMac, ADDR_TYPE_ETH, ETH_ADDR_BITS, &eth->eth_dst, ETH_ADDR_LEN);

	addr srcMac;
	addr_pack(&srcMac, ADDR_TYPE_ETH, ETH_ADDR_BITS, &eth->eth_src, ETH_ADDR_LEN);

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

			if (addr_cmp(&addr, &CI->m_srcip) == 0)
			{
				cout << "Got an ARP request to " << addr_ntoa(&dstMac) << " for IP " << addr_ntoa(&addr) << " from " << addr_ntoa(&srcMac) << endl;

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
			if (pkthdr->len != prober.probeBufferSize)
				return;

			for (int i = 0; i < pkthdr->len; i++)
			{
				if (packet[i] != prober.probeBuffer[i])
				{
					return;
				}
			}

			seenProbe = true;
			cout << "Packet capture thread has seen probe packet go out" << endl;
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

int main(int argc, char ** argv)
{
	Config::Inst()->LoadArgs(argv, argc);
	



	InterfacePacketCapture *capture = new InterfacePacketCapture(CI->m_interface);
	capture->Init();
	capture->SetPacketCb(&packetCallback);

	stringstream ss;
	ss << "arp or (dst host " << CI->m_srcipString << ")";
	capture->SetFilter(ss.str());

	capture->StartCapture();

	// Wait a bit for the capture thread to get going
	sleep(1);


	prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, CI->m_dstport, CI->m_srcport);

	// TODO: 6 seconds should probably be an option. Will figure out timing configuration once more tests written
	sleep(CI->m_sleeptime);
	cout << fingerprint.toString() << endl << endl;

	return 0;
}


