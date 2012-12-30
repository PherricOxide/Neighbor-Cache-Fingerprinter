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
//   along with Nova.  If not, see <http://www.gnu.org/licenses/>.
//============================================================================

#include <iostream>
#include <dumbnet.h>
#include <cstring>
#include <sstream>
#include <pthread.h>

#include "InterfacePacketCapture.h"
#include "Fingerprinter.h"
#include "ArpFingerprint.h"
#include "Config.h"
#include "Probes.h"
#include "helpers.h"
#include "Lock.h"

using namespace std;
using namespace Nova;


pthread_mutex_t cbLock;
ResponseBehavior response;
ArpFingerprint fingerprint;
bool seenProbe = false;
bool replyToArp = false;

addr broadcastMAC, broadcastIP, zeroIP, zeroMAC, origSrcMac;

Prober prober;

timeval lastARPReply; /* Used to compute the time between ARP requests */

string horizontalLine = "======================================================================";

// TODO: Do this a better way (don't loop at 255, don't use addr internals)
void incrementSourceMac() {
	CI->m_srcmac.__addr_u.__eth.data[5]++;
}

// TODO: The response variable is how we get info back from the callback.
// This is a hacky way to do it left over from the initial prototype,
// the entire callback function really needs refactoring at some point.
void ResetResponse(bool setSeenProbe) {
	pthread_mutex_lock(&cbLock);
	seenProbe = setSeenProbe;
	response = ResponseBehavior();
	pthread_mutex_unlock(&cbLock);
}

void packetCallback(unsigned char *index, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
	Lock lock(&cbLock);

	if (pkthdr->len < ETH_HDR_LEN)
		return;

	eth_hdr *eth = (eth_hdr*)packet;
	addr dstMac, srcMac;

	addr_pack_eth(&dstMac, (uint8_t*)&eth->eth_dst);
	addr_pack_eth(&srcMac, (uint8_t*)&eth->eth_src);

	if (ntohs(eth->eth_type) == ETH_TYPE_ARP) {
		/* We ignore everything before our probe has been sent */
		if (!seenProbe)
			return;

		if (pkthdr->len < ETH_HDR_LEN + ARP_HDR_LEN)
			return;

		arp_hdr *arp = (arp_hdr*)(packet + ETH_HDR_LEN);
		if (ntohs(arp->ar_op) == ARP_OP_REQUEST) {
			if (pkthdr->len < ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN)
				return;

			arp_ethip *arpRequest = (arp_ethip*)(packet + ETH_HDR_LEN + ARP_HDR_LEN);
			addr addr;
			addr_pack_ip(&addr, arpRequest->ar_tpa);


			if (addr_cmp(&addr, &CI->m_srcip) == 0) {
				cout << "<< Got an ARP request to " << addr_ntoa(&dstMac) << " for IP " << addr_ntoa(&addr) << " from " << addr_ntoa(&srcMac) << endl;

				if (addr_cmp(&dstMac, &CI->m_srcmac) == 0) {
					response.unicastUpdate = true;
				} else if (addr_cmp(&dstMac, &broadcastMAC) == 0) {
					response.unicastUpdate = false;
				} else {
					cout << "WARNING: Got an ARP packet that was neither to the broadcast MAC or our probe MAC. This is unusual." << endl;
				}

				response.requestAttempts++;

				if (replyToArp)
					prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);

				int diff = 0;
				diff += 1000000*(pkthdr->ts.tv_sec  - lastARPReply.tv_sec);
				diff += pkthdr->ts.tv_usec - lastARPReply.tv_usec;

				if (response.requestAttempts > 1 && response.requestAttempts < MAX_RECORDED_REPLIES) {
					response.timeBetweenRequests[response.requestAttempts - 2] = diff;

					/* Compute the average time between requests */
					double sum = 0;
					for (int i = 0; i < (response.requestAttempts - 1); i++)
						sum += response.timeBetweenRequests[i];
					response.averageTimeBetweenRequests = sum / (response.requestAttempts - 1);

					if (diff > response.m_maxTimebetweenRequests) {
						response.m_maxTimebetweenRequests = diff;
					}
					if (diff < response.m_minTimeBetweenRequests) {
						response.m_minTimeBetweenRequests = diff;
					}
				}
				lastARPReply = pkthdr->ts;
			}
		} else if (ntohs(arp->ar_op) == ARP_OP_REPLY) {
			if (pkthdr->len < ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN)
				return;

			arp_ethip *arpRequest = (arp_ethip*)(packet + ETH_HDR_LEN + ARP_HDR_LEN);
			addr addr;
			addr_pack_ip(&addr, arpRequest->ar_tpa);

			// Drop it if not to broadcast or our current srcmac
			if (addr_cmp(&broadcastMAC, &dstMac) != 0 && addr_cmp(&CI->m_srcmac, &dstMac) != 0)
				return;

			addr_pack_ip(&response.tpa, arpRequest->ar_tpa);
			addr_pack_eth(&response.tha, arpRequest->ar_tha);
			addr_pack_ip(&response.spa, arpRequest->ar_spa);
			addr_pack_eth(&response.sha, arpRequest->ar_sha);

			// Drop it if not from our target IP
			if (addr_cmp(&response.spa, &CI->m_dstip) != 0)
				return;

			response.sawArpReply = true;

			cout << "<< Got an ARP reply to " << addr_ntoa(&dstMac) << " for IP " << addr_ntoa(&response.spa) << " from " << addr_ntoa(&srcMac) << endl;
		}

	} else if (ntohs(eth->eth_type) == ETH_TYPE_IP) {
		if (pkthdr->len < ETH_HDR_LEN + IP_HDR_LEN)
			return;

		ip_hdr *ip = (ip_hdr*)(packet + ETH_HDR_LEN);

		/* Check if our own probe packet went over the interface */
		if (!seenProbe) {
			Lock lock(&prober.probeBufferLock);
			if (pkthdr->len != prober.probeBufferSize)
				return;

			for (int i = 0; i < pkthdr->len; i++) {
				if (packet[i] != prober.probeBuffer[i])
					return;
			}

			seenProbe = true;
			//cout << "Packet capture thread has seen probe packet go out" << endl;
		} else {
			addr dstIp, srcIp;
			addr_pack_ip(&dstIp, (uint8_t*)&ip->ip_dst);
			addr_pack_ip(&srcIp, (uint8_t*)&ip->ip_src);


			if (addr_cmp(&dstIp, &CI->m_srcip) == 0) {
				response.dstMac = dstMac;
				response.srcMac = srcMac;
				if (addr_cmp(&dstMac, &CI->m_srcmac) == 0) {
					response.replyToCorrectMAC = true;
				} else {
					response.replyToCorrectMAC = false;
				}

				cout << "<< Saw a probe response to " << addr_ntoa(&dstIp) << " / " << addr_ntoa(&dstMac) << " from " << addr_ntoa(&srcIp) << " / " << addr_ntoa(&srcMac) << endl;
				response.sawProbeReply = true;
				if (response.requestAttempts == 0)
					response.replyBeforeARP = true;
				else
					response.replyBeforeARP = false;
			}

		}
	}
}

// Find the destination MAC address for our target if not specified on CLI
void ConfigureDestinationMAC() {
	// Check if dstmac already set
	if (addr_cmp(&CI->m_dstmac, &zeroMAC) == 0) {
		cout << "Attempting to find MAC address of target via ARP" << endl;

		// Don't drop packets because we're not doing a probe here
		ResetResponse(true);

		prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &zeroIP, &CI->m_dstip, ARP_OP_REQUEST, &zeroMAC);
		sleep(2);

		pthread_mutex_lock(&cbLock);
		if (response.sawArpReply) {
			CI->m_dstmac = response.sha;
			cout << "Setting target MAC address to " << addr_ntoa(&response.sha) << endl;
		} else {
			cout << "ERROR: Did not see a reply to our ARP probe! Unable to perform scan." << endl;
			cout << "Please check that the target host is up. If it is, you can specify it's MAC with --dstmac to bypass this step." << endl;
			exit(1);
		}

		pthread_mutex_unlock(&cbLock);


	}
}

// This is used in the gratuitous ARP test for checking the result
bool gratuitousResultCheck() {
	bool result;

	prober.SendSYN(CI->m_dstip, CI->m_dstmac, CI->m_srcip, origSrcMac, CI->m_dstport, CI->m_srcport);
	usleep(1000000);

	pthread_mutex_lock(&cbLock);
	if (!response.sawProbeReply) {
		cout << "WARNING: Saw no probe response! Unable to perform test." << endl;
	}

	if (response.replyToCorrectMAC) {
		result = true;
		cout << "PASS: Gratuitous ARP was accepted into the cache" << endl << endl;
	} else {
		result = false;
		cout << "FAIL: Gratuitous ARP was NOT accepted into the cache" << endl << endl;;
	}

	response = ResponseBehavior();
	seenProbe = false;
	incrementSourceMac();

	pthread_mutex_unlock(&cbLock);
	return result;
}

void checkInitialQueryBehavior()
{
	cout << horizontalLine << endl;
	cout << "Checking initial response to probe" << endl;
	cout << horizontalLine << endl;

	for (int i = 0; i < CI->m_retries; i++) {
		prober.Probe();
		sleep(CI->m_sleeptime);

		pthread_mutex_lock(&cbLock);
		cout << response.toString() << endl;


		if (response.requestAttempts > fingerprint.requestAttemptsMax) {
			fingerprint.requestAttemptsMax = response.requestAttempts;
		}

		if (response.requestAttempts < fingerprint.requestAttemptsMin){
			fingerprint.requestAttemptsMin = response.requestAttempts;
		}

		// Reset response if this isn't the last test
		if (i != CI->m_retries - 1) {
			// Save the min and max times
			ResponseBehavior f;
			f.m_maxTimebetweenRequests = response.m_maxTimebetweenRequests;
			f.m_minTimeBetweenRequests = response.m_minTimeBetweenRequests;
			response = f;
		}
		pthread_mutex_unlock(&cbLock);
	}


	// Populate our results into the fingerprint
	double difference = response.m_maxTimebetweenRequests - response.m_minTimeBetweenRequests;
	double percentDifference = 100*difference/response.m_minTimeBetweenRequests;
	cout << "Timing range difference of " << percentDifference << endl;

	if (percentDifference > 8) {
		fingerprint.constantRetryTime = false;
	} else {
		fingerprint.constantRetryTime = true;
	}

	fingerprint.maxTimeBetweenRetries = response.m_maxTimebetweenRequests;
	fingerprint.minTimeBetweenRetries = response.m_minTimeBetweenRequests;
}


/*
 * Test Purpose
 *     This checks if an unsolicited reply can create a neighbor entry or update
 *   one that's in an invalid state.
 *
 * Target State Prerequisite
 *     We assume that the we're not currently in the neighbor cache or are
 *   in an invalid state and will NOT reply to probes until the ARP entry
 *   is verified. If this is not the case, results of this test will be bogus.
 *
 * Test Overview
 *   >> Send a standard unicast ARP Reply (as if the host send us a REQUEST)
 *   >> Send a probe
 *   << Wait for probe response
 *   If we got a probe response,
 *     We know that the unsolicited reply created/updated the cache entry
*/
void checkInitialUnsolictedReply() {
	cout << horizontalLine << endl;
	cout << "Checking if unsolicited reply creates cache entry" << endl;
	cout << horizontalLine << endl;

	prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);
	sleep(1);
	prober.Probe();
	sleep(1);

	pthread_mutex_lock(&cbLock);
	cout << response.toString() << endl;

	if (response.sawProbeReply) {
		fingerprint.gratuitousReplyAddsCacheEntry = true;
	} else {
		fingerprint.gratuitousReplyAddsCacheEntry = false;
	}
	pthread_mutex_unlock(&cbLock);
}


void checkStaleTiming() {
	cout << horizontalLine << endl;
	cout << "Checking how long before cache entry expires" << endl;
	cout << horizontalLine << endl;

	// TODO: What do we do about the max for this? Could take 20 mins on freebsd
	// For now we just go up to a max of 1 min? Should have option to go longer.
	int i;
	for (i = 0; i < 60; i++) {
		cout << endl << "Sending probe " << i + 1 << " of " << 60 << endl;
		pthread_mutex_lock(&cbLock);
		response = ResponseBehavior();
		seenProbe = false;

		// Only reply to the 1st ARP request in this test
		if (i == 0)
			replyToArp = true;
		else
			replyToArp = false;
		pthread_mutex_unlock(&cbLock);

		prober.Probe();

		sleep(1);

		pthread_mutex_lock(&cbLock);
		if (response.requestAttempts > 0 && i != 0) {
			break;
		}
		pthread_mutex_unlock(&cbLock);
	}

	fingerprint.referencedStaleTimeout = i;
	fingerprint.replyBeforeUpdate = response.sawProbeReply;
	fingerprint.unicastUpdate = response.unicastUpdate;

	pthread_mutex_unlock(&cbLock);
}

void checkGratuitousBehavior() {
	cout << horizontalLine << endl;
	cout << "Checking if cache is updated with various unsolicited ARP packets" << endl;
	cout << horizontalLine << endl;

	origSrcMac = CI->m_srcmac;

	pthread_mutex_lock(&cbLock);
	replyToArp = true;
	pthread_mutex_unlock(&cbLock);


	// Get ourselves into the ARP cache
	prober.Probe();

	sleep(5);

	pthread_mutex_lock(&cbLock);
	response = ResponseBehavior();
	seenProbe = false;
	replyToArp = false;
	incrementSourceMac();
	pthread_mutex_unlock(&cbLock);

	int probeTestNumber = 0;
	bool results[36];

	stringstream result;
	// Try for both ARP request and ARP reply opcodes
	for (int arpOpCode = 2; arpOpCode > 0; arpOpCode--) {
		for (int macDestination = 0; macDestination < 2; macDestination++) {
			for (int tpa = 0; tpa < 3; tpa++) {
				for (int tha = 0; tha < 3; tha++){
					cout << endl << "Starting test " << probeTestNumber + 1 << " of 36" << endl;

					addr tpaAddress;
					if (tpa == 0) {
						tpaAddress = zeroIP;
					} else if (tpa == 1) {
						tpaAddress = CI->m_srcip;
					} else if (tpa == 2) {
						tpaAddress = CI->m_dstip;
					}

					addr thaAddress;
					if (tha == 0) {
						thaAddress = zeroMAC;
					} else if (tha == 1) {
						thaAddress = broadcastMAC;
					} else if (tha == 2) {
						thaAddress = CI->m_dstmac;
					}


					// Ethernet frame destination MAC
					addr destinationMac;
					if (macDestination == 0) {
						destinationMac = broadcastMAC;
					} else if (macDestination == 1) {
						destinationMac = CI->m_dstmac;
					}

					prober.SendARPReply(&CI->m_srcmac, &destinationMac, &CI->m_srcip, &tpaAddress, arpOpCode, &thaAddress);
					usleep(1000000);

					bool testResult = gratuitousResultCheck();
					result << testResult;

					if (probeTestNumber >= 36) {
						cout << "ERROR: Invalid gratuitous probe number!" << endl;
						exit(1);
					}

					results[probeTestNumber] = testResult;
					probeTestNumber++;

					prober.SendARPReply(&origSrcMac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);
					sleep(3);
					ResetResponse(false);
				}
			}
		}
	}

	for (int i = 0; i < 36; i++) {
		fingerprint.gratuitousUpdates[i] = results[i];
	}

	cout << "Result fingerprint from gratuitous test," << endl;
	cout << result.str() << endl;
}

void checkForFloodProtection() {
	cout << horizontalLine << endl;
	cout << "Checking if target has ARP flood protection" << endl;
	cout << horizontalLine << endl;

	int start = CI->m_srcmac.__addr_u.__eth.data[5];
	for (int i = 0; i < 6; i++) {
		incrementSourceMac();
		prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);
		usleep(250000);
	}

	ResetResponse(false);

	prober.Probe();
	sleep(2);

	pthread_mutex_lock(&cbLock);
	cout << "Reply was to " << addr_ntoa(&response.dstMac) << endl;
	cout << "count was " << response.dstMac.__addr_u.__eth.data[5] - start << endl;

	if (response.dstMac.__addr_u.__eth.data[5] - start == 0) {
		cout << "ERROR: None of the replies were accepted into the cache! Can not determine result for this test." << endl;
		fingerprint.hasFloodProtection = false;
	} else if (response.dstMac.__addr_u.__eth.data[5] - start == 1) {
		fingerprint.hasFloodProtection = true;
		cout << "ARP flood protection was detected" << endl;
	} else {
		cout << "No ARP flood protection detected" << endl;
		fingerprint.hasFloodProtection = false;
	}

	pthread_mutex_unlock(&cbLock);
}



/*
 * Test Purpose
 *   This was a test written orginally written to detect the patch in the
 *   Linux 2.6.24 Kernel, git commit b4a9811c42ecb70b2f0b375f6d4c77ab34d1f598
 *
 * Target State Prerequisites
 *   None.
 *
 * Test Details
 *   This test sends an "ARP Probe" as defined by RFC 5227 (IPv4 Address Conflict Detection) and
 *   checks the response to see if it confirms to the specification.
 *
 *   The RFC specifies the response as,
 *
 *     (the probed host) MAY elect to attempt to defend its address by
 *      ... broadcasting one single ARP Announcement, giving its own
 *      IP and hardware addresses as the sender addresses of the ARP,
 *      with the 'target IP address' set to its own IP address, and the
 *      'target hardware address' set to all zeroes.
 *
 *     But any Linux kernel older than 2.6.24 and some other operating systems will respond incorrectly,
 *   with a packet that has tpa == spa and tha == sha. Checking if tpa == 0 has proven sufficient for
 *   a boolean fingerprint feature.
 */
void checkIsIpUsedResponse() {
	cout << horizontalLine << endl;
	cout << "Checking if target replies properly to RFC5227 ARP Probe" << endl;
	cout << horizontalLine << endl;

	ResetResponse(true);

	prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &zeroIP, &CI->m_dstip, ARP_OP_REQUEST, &zeroMAC);
	sleep(2);

	pthread_mutex_lock(&cbLock);
	cout << "Response follows," << endl;
	if (response.sawArpReply) {
		cout << "spa: " << addr_ntoa(&response.spa) << endl;
		cout << "sha: " << addr_ntoa(&response.sha) << endl;
		cout << "tpa: " << addr_ntoa(&response.tpa) << endl;
		cout << "tha: " << addr_ntoa(&response.tha) << endl;

		if (addr_cmp(&response.tpa, &zeroIP) == 0) {
			fingerprint.correctARPProbeResponse  = true;
		} else {
			fingerprint.correctARPProbeResponse = false;
		}
	} else {
		cout << "ERROR: Did not see a reply to our ARP probe" << endl;
		fingerprint.correctARPProbeResponse = false;
	}

	cout << "Target correctly responded to ARP Probe: " << fingerprint.correctARPProbeResponse  << endl;

	pthread_mutex_unlock(&cbLock);
}


int main(int argc, char ** argv)
{
	Config::Inst()->LoadArgs(argv, argc);

	// Load the fingerprints
	Fingerprinter fingerprinter;
	fingerprinter.LoadFingerprints();

	/* Stuff the broadcast MAC in an addr type for comparison later */
	unsigned char broadcastBuffer[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	addr_pack_eth(&broadcastMAC, (uint8_t*)broadcastBuffer);

	// Random note: 192.168.0.2 = ntohl(0xc0a80002);
	uint32_t bcastNumber = ~0;
	addr_pack_ip(&broadcastIP, (uint8_t*)&bcastNumber);

	// Stuff the zero value into an ip addr
	uint32_t zeroNumber = 0;
	addr_pack_ip(&zeroIP, (uint8_t*)&zeroNumber);

	// Stuff the zerio value into a MAC addr
	uint8_t zeroMacNumber[6];
	for (int i = 0; i < 6; i++)
		zeroMacNumber[i] = 0;
	addr_pack_eth(&zeroMAC, &zeroMacNumber[0]);

	stringstream pcapFilterString;
	pcapFilterString << "arp or (dst host " << CI->m_srcipString << ")";

	pthread_mutex_init(&cbLock, NULL);

	
	InterfacePacketCapture *capture = new InterfacePacketCapture(CI->m_interface);
	capture->Init();
	capture->SetFilter(pcapFilterString.str());
	capture->SetPacketCb(&packetCallback);
	capture->StartCapture();
	sleep(1);

	// Get the MAC of our target
	ConfigureDestinationMAC();


	// This one doesn't update ARP cache on Linux 2.6 but seems to work in Linux 3.x.
	// The rest all work to update the cache but not to create new entry in Linux.
	if (CI->m_test == 100) {
		prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, &CI->m_srcip);
		return 0;
	}

	if (CI->m_test == 101) {
		prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, (addr*)&zeroIP);
		return 0;
	}

	// This one adds an entry to the ARP cache in FreeBSD
	if (CI->m_test == 102) {
		prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);
		return 0;
	}

	if (CI->m_test == 103) {
		prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, (addr*)&zeroIP);
		return 0;
	}

	if (CI->m_test == 104) {
		prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, &CI->m_dstip, ARP_OP_REQUEST, &zeroMAC);
		return 0;
	}

	if (CI->m_test == 105) {
		prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, &broadcastIP, ARP_OP_REQUEST, &zeroMAC);
		sleep(2);
		prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &broadcastIP, ARP_OP_REQUEST, &zeroMAC);
		return 0;
	}

	if (CI->m_test == 200) {
		prober.Probe();
		return 0;
	}


	if (CI->m_test == 0) {
		checkInitialQueryBehavior();
		checkInitialUnsolictedReply();
		checkStaleTiming();
		sleep(3);
		checkGratuitousBehavior();
		checkForFloodProtection();
		checkIsIpUsedResponse();

		cout << endl;
		cout << fingerprint.toString() << endl << endl;

		cout << "FINGERPRINT BEGINS" << endl;
		cout << fingerprint.toTinyString() << endl;
		cout << "FINGERPRINT ENDS" << endl << endl;

		cout << "Fingerprint matches follow (best matches being first)" << endl;
		cout << fingerprinter.GetMatchReport(fingerprint) << endl;
	}

	if (CI->m_test == 1) {
		checkInitialQueryBehavior();
	}

	if (CI->m_test == 2) {
		checkStaleTiming();
	}

	if (CI->m_test == 3) {
		/*
		 * We run this test twice to note a neat difference between Windows and Linux.
		 * In Linux, the first probe packet will cause the SYN/RST to put an entry in the ARP cache, which will be
		 * set to FAIL state and then updated to STALE when it sees the gratuitous ARP, causing the 2nd probe to
		 * be replied to followed by ARP requests. Windows 7 at least will ignore the gratuitous ARP packet
		 * entirely and not exhibit the same behavior.
		*/

		/* This has mostly been depricated by test #4. Both OSes do pay attention to some forms of unsolicited
		 * ARP packets if the neighbor is already in the cach.
		 *
		 */
		for (int i = 0; i < 2; i++) {
			ResetResponse(false);

			// Send gratuitous ARP reply
			prober.SendARPReply(&CI->m_srcmac, &broadcastMAC, &CI->m_srcip, &CI->m_srcip);


			prober.Probe();
			sleep(CI->m_sleeptime);
			pthread_mutex_lock(&cbLock);
			cout << response.toString() << endl << endl;
			pthread_mutex_unlock(&cbLock);

		}
	}

	if (CI->m_test == 4) {
		checkGratuitousBehavior();
	}

	// Should already be in the ARP cache before calling this
	// TODO check for bad results from not being in the cache already
	if (CI->m_test == 5) {
		checkForFloodProtection();
	}

	// Should already be in the ARP cache
	// TODO check for bad results from not being in the ARP cache already
	if (CI->m_test == 6) {
		int start;
		for (int i = 15; i < 30; i++) {
			start = CI->m_srcmac.__addr_u.__eth.data[5];

			incrementSourceMac();
			prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);
			usleep(i*50000);
			cout << "Delay was (ms): " << i*50 << endl;
			incrementSourceMac();
			prober.SendARPReply(&CI->m_srcmac, &CI->m_dstmac, &CI->m_srcip, &CI->m_dstip);

			ResetResponse(false);

			prober.Probe();

			sleep(2);
			pthread_mutex_lock(&cbLock);
			if (response.sawProbeReply) {
				cout << "Reply was to " << addr_ntoa(&response.dstMac) << endl;
				cout << "count was " << response.dstMac.__addr_u.__eth.data[5] - start << endl;
			} else {
				cout << "ERROR: Test failed because we saw no reply to our probe." << endl;
			}
			pthread_mutex_unlock(&cbLock);

		}
	}

	// should NOT be in the ARP cache before calling this
	if (CI->m_test == 7) {
		checkInitialUnsolictedReply();
	}


	if (CI->m_test == 8) {
		checkIsIpUsedResponse();
	}


	return 0;
}

