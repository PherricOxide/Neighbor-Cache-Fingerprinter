#include <iostream>
#include <dumbnet.h>
#include <cstring>
#include <sstream>
#include <pthread.h>

#include "InterfacePacketCapture.h"
#include "ArpFingerprint.h"
#include "Config.h"
#include "Probes.h"
#include "helpers.h"
#include "Lock.h"

using namespace std;
using namespace Nova;


// TOOD: Might want to move state data out of the fingerprint and into per test structs of some sort
pthread_mutex_t cbLock;
ArpFingerprint fingerprint;
bool seenProbe = false;
bool replyToArp = false;

Prober prober;

timeval lastARPReply; /* Used to compute the time between ARP requests */

void packetCallback(unsigned char *index, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
	Lock lock(&cbLock);

	if (pkthdr->len < ETH_HDR_LEN)
		return;

	eth_hdr *eth = (eth_hdr*)packet;
	addr dstMac, srcMac, broadcastMAC;

	addr_pack_eth(&dstMac, (uint8_t*)&eth->eth_dst);
	addr_pack_eth(&srcMac, (uint8_t*)&eth->eth_src);

	/* Stuff the broadcast MAC in an addr type for comparison later */
	unsigned char broadcastBuffer[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	addr_pack_eth(&broadcastMAC, (uint8_t*)broadcastBuffer);

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
			addr_pack_ip(&addr, arpRequest->ar_tpa);


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

				if (replyToArp)
					prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);

				int diff = 0;
				diff += 1000000*(pkthdr->ts.tv_sec  - lastARPReply.tv_sec);
				diff += pkthdr->ts.tv_usec - lastARPReply.tv_usec;
				cout << "Time since last ARP request was " << pkthdr->ts.tv_sec  - lastARPReply.tv_sec << " seconds " << endl;


				if (fingerprint.arpRequests > 1 && fingerprint.arpRequests < MAX_RECORDED_REPLIES)
				{
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
			Lock lock(&prober.probeBufferLock);
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
			addr_pack_ip(&dstIp, (uint8_t*)&ip->ip_dst);

			if (addr_cmp(&dstIp, &CI->m_srcip) == 0 && addr_cmp(&dstMac, &CI->m_srcmac) == 0)
			{
				fingerprint.sawTCPResponse = true;
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

	stringstream pcapFilterString;
	pcapFilterString << "arp or (dst host " << CI->m_srcipString << ")";

	pthread_mutex_init(&cbLock, NULL);

	
	InterfacePacketCapture *capture = new InterfacePacketCapture(CI->m_interface);
	capture->Init();
	capture->SetFilter(pcapFilterString.str());
	capture->SetPacketCb(&packetCallback);
	capture->StartCapture();
	sleep(1);

	prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, CI->m_dstport, CI->m_srcport);
	sleep(CI->m_sleeptime);

	pthread_mutex_lock(&cbLock);
	cout << fingerprint.toString() << endl << endl;
	pthread_mutex_unlock(&cbLock);


	for (int i = 0; i < 140; i++)
	{
		pthread_mutex_lock(&cbLock);
		fingerprint = ArpFingerprint();
		seenProbe = false;

		// Only reply to the 1st ARP request in this test
		if (i == 0)
			replyToArp = true;
		else
			replyToArp = false;

		prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, CI->m_dstport, CI->m_srcport);
		pthread_mutex_unlock(&cbLock);

		sleep(1);

		pthread_mutex_lock(&cbLock);
		cout << fingerprint.toString() << endl << endl;
		if (fingerprint.arpRequests > 0 && i != 0)
			break;
		pthread_mutex_unlock(&cbLock);

	}


	return 0;
}


