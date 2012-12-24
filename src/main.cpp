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

addr broadcastMAC, zeroIP, zeroMAC;

Prober prober;

timeval lastARPReply; /* Used to compute the time between ARP requests */

void packetCallback(unsigned char *index, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
	Lock lock(&cbLock);

	if (pkthdr->len < ETH_HDR_LEN)
		return;

	eth_hdr *eth = (eth_hdr*)packet;
	addr dstMac, srcMac;

	addr_pack_eth(&dstMac, (uint8_t*)&eth->eth_dst);
	addr_pack_eth(&srcMac, (uint8_t*)&eth->eth_src);

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

					if (diff > fingerprint.m_maxTimebetweenRequests)
					{
						fingerprint.m_maxTimebetweenRequests = diff;
					}
					if (diff < fingerprint.m_minTimeBetweenRequests)
					{
						fingerprint.m_minTimeBetweenRequests = diff;
					}
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
			//cout << "Packet capture thread has seen probe packet go out" << endl;
		}
		else
		{
			addr dstIp, srcIp;
			addr_pack_ip(&dstIp, (uint8_t*)&ip->ip_dst);
			addr_pack_ip(&srcIp, (uint8_t*)&ip->ip_src);


			if (addr_cmp(&dstIp, &CI->m_srcip) == 0)
			{
				if (addr_cmp(&dstMac, &CI->m_srcmac) == 0)
				{
					fingerprint.replyToCorrectMAC = true;
				}
				else
				{
					fingerprint.replyToCorrectMAC = false;
				}


				cout << "Saw a TCP response to " << addr_ntoa(&dstIp) << " / " << addr_ntoa(&dstMac) << " from " << addr_ntoa(&srcIp) << " / " << addr_ntoa(&srcMac) << endl;
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

	/* Stuff the broadcast MAC in an addr type for comparison later */
	unsigned char broadcastBuffer[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	addr_pack_eth(&broadcastMAC, (uint8_t*)broadcastBuffer);

	uint32_t zeroNumber = 0;
	addr zero;
	addr_pack_ip(&zeroIP, (uint8_t*)&zeroNumber);


	stringstream pcapFilterString;
	pcapFilterString << "arp or (dst host " << CI->m_srcipString << ")";

	pthread_mutex_init(&cbLock, NULL);

	
	InterfacePacketCapture *capture = new InterfacePacketCapture(CI->m_interface);
	capture->Init();
	capture->SetFilter(pcapFilterString.str());
	capture->SetPacketCb(&packetCallback);
	capture->StartCapture();
	sleep(1);


	// This one doesn't update ARP tables on Linux 2.6 but seems to work in Linux 3.x.
	// The rest all work to update the table but not to create new entry in Linux.
	if (CI->m_test == 100)
	{
		prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, &CI->m_srcip);
		return 0;
	}

	if (CI->m_test == 101)
	{
		prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, (addr*)&zeroIP);
		return 0;
	}

	// This one adds an entry to the ARP table in FreeBSD
	if (CI->m_test == 102)
	{
		prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);
		return 0;
	}

	if (CI->m_test == 103)
	{
		prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, (addr*)&zeroIP);
		return 0;
	}

	if (CI->m_test == 200)
	{
		prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, CI->m_dstport, CI->m_srcport);
		return 0;
	}

	if (CI->m_test == 1)
	{
		for (int i = 0; i < CI->m_retries; i++)
		{
			prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, CI->m_dstport, CI->m_srcport);
			sleep(CI->m_sleeptime);

			pthread_mutex_lock(&cbLock);
			cout << fingerprint.toString() << endl << endl;
			// Save the min and max times
			ArpFingerprint f;
			f.m_maxTimebetweenRequests = fingerprint.m_maxTimebetweenRequests;
			f.m_minTimeBetweenRequests = fingerprint.m_minTimeBetweenRequests;
			fingerprint = f;
			pthread_mutex_unlock(&cbLock);
		}
	}

	if (CI->m_test == 2)
	{
		for (int i = 0; i < 660; i++)
		{
			pthread_mutex_lock(&cbLock);
			fingerprint = ArpFingerprint();
			seenProbe = false;

			// Only reply to the 1st ARP request in this test
			if (i == 0)
				replyToArp = true;
			else
				replyToArp = false;
			pthread_mutex_unlock(&cbLock);

			prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, CI->m_dstport, CI->m_srcport);

			sleep(1);

			pthread_mutex_lock(&cbLock);
			cout << fingerprint.toString() << endl << endl;
			if (fingerprint.arpRequests > 0 && i != 0)
			{
				pthread_mutex_unlock(&cbLock);
				break;
			}
			pthread_mutex_unlock(&cbLock);
		}
	}

	if (CI->m_test == 3) {
		/*
		 * We run this test twice to note a neat difference between Windows and Linux.
		 * In Linux, the first TCP packet will cause the SYN/RST to put an entry in the ARP table, which will be
		 * set to FAIL state and then updated to STALE when it sees the gratuitous ARP, causing the 2nd probe to
		 * be replied to followed by ARP requests. Windows 7 at least will ignore the gratuitous ARP packet
		 * entirely and not exhibit the same behavior.
		*/
		for (int i = 0; i < 2; i++)
		{
			pthread_mutex_lock(&cbLock);
			fingerprint = ArpFingerprint();
			seenProbe = false;
			pthread_mutex_unlock(&cbLock);


			// Send gratuitous ARP reply
			addr zero;
			uint32_t zeroIp = 0;
			addr_pack_ip(&zero, (uint8_t*)&zeroIp);
			prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, &CI->m_srcip);


			prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, CI->m_dstport, CI->m_srcport);
			sleep(CI->m_sleeptime);
			pthread_mutex_lock(&cbLock);
			cout << fingerprint.toString() << endl << endl;
			pthread_mutex_unlock(&cbLock);

		}
	}

	if (CI->m_test == 4)
	{
		addr origSrcMac = CI->m_srcmac;

		pthread_mutex_lock(&cbLock);
		replyToArp = true;
		pthread_mutex_unlock(&cbLock);


		// Get ourselves into the ARP table
		prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, CI->m_srcmac, CI->m_dstport, CI->m_srcport);

		sleep(2);

		pthread_mutex_lock(&cbLock);
		fingerprint = ArpFingerprint();
		seenProbe = false;
		replyToArp = false;
		CI->m_srcmac.__addr_u.__eth.data[5]++;
		pthread_mutex_unlock(&cbLock);

		prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, &CI->m_srcip);
		prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, origSrcMac, CI->m_dstport, CI->m_srcport);
		sleep(2);

		pthread_mutex_lock(&cbLock);

		if (!fingerprint.sawTCPResponse)
		{
			cout << "Warning: Saw no TCP response! Unable to perform test." << endl;
			return 1;
		}

		if (fingerprint.replyToCorrectMAC)
		{
			cout << "PASS: Gratuitous ARP was accepted into the table" << endl << endl;
		}
		else
		{
			cout << "FAIL: Gratuitous ARP was NOT accepted into the table" << endl << endl;;
		}

		fingerprint = ArpFingerprint();
		seenProbe = false;
		CI->m_srcmac.__addr_u.__eth.data[5]++;
		pthread_mutex_unlock(&cbLock);



		// Test 2
		prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, (addr*)&zeroIP);
		prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, origSrcMac, CI->m_dstport, CI->m_srcport);
		sleep(2);

		pthread_mutex_lock(&cbLock);
		if (!fingerprint.sawTCPResponse)
		{
			cout << "Warning: Saw no TCP response! Unable to perform test." << endl;
			return 1;
		}

		if (fingerprint.replyToCorrectMAC)
		{
			cout << "PASS: Gratuitous ARP was accepted into the table" << endl << endl;
		}
		else
		{
			cout << "FAIL: Gratuitous ARP was NOT accepted into the table" << endl << endl;;
		}

		fingerprint = ArpFingerprint();
		seenProbe = false;
		CI->m_srcmac.__addr_u.__eth.data[5]++;
		pthread_mutex_unlock(&cbLock);


		// Test 3
		prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);
		prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, origSrcMac, CI->m_dstport, CI->m_srcport);
		sleep(2);

		pthread_mutex_lock(&cbLock);
		if (!fingerprint.sawTCPResponse)
		{
			cout << "Warning: Saw no TCP response! Unable to perform test." << endl;
			return 1;
		}

		if (fingerprint.replyToCorrectMAC)
		{
			cout << "PASS: Gratuitous ARP was accepted into the table" << endl << endl;
		}
		else
		{
			cout << "FAIL: Gratuitous ARP was NOT accepted into the table" << endl << endl;;
		}

		fingerprint = ArpFingerprint();
		seenProbe = false;
		CI->m_srcmac.__addr_u.__eth.data[5]++;
		pthread_mutex_unlock(&cbLock);


		// Test 4
		prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, (addr*)&zeroIP);
		prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, origSrcMac, CI->m_dstport, CI->m_srcport);
		sleep(2);

		pthread_mutex_lock(&cbLock);
		if (!fingerprint.sawTCPResponse)
		{
			cout << "Warning: Saw no TCP response! Unable to perform test." << endl;
			return 1;
		}

		if (fingerprint.replyToCorrectMAC)
		{
			cout << "PASS: Gratuitous ARP was accepted into the table" << endl << endl;
		}
		else
		{
			cout << "FAIL: Gratuitous ARP was NOT accepted into the table" << endl << endl;;
		}

		pthread_mutex_unlock(&cbLock);
	}


	return 0;
}


