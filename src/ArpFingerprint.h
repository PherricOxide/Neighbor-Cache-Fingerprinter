#ifndef ARPFINGERPRINT_H
#define ARPFINGERPRINT_H

#include <sstream>
#include <stdint.h>
#include <string>

#define MAX_RECORDED_REPLIES 10

class ArpFingerprint
{
public:
	std::string name;

	// Number of attempts to send an ARP request if no response is given
	int requestAttempts;

	// Are the timings between retries constant? Or is there greater than 8% variation?
	bool constantRetryTime;

	// How often does the target try to send new requests to update it's cache value?
	// When the entry is in use?
	int referencedStaleTimeout;

	// Do we see a reply before an ARP request when the cache entry becomes stale?
	bool replyBeforeUpdate;

	// Are requests to update the entry sent to the MAC of the machine instead of the bcast address?
	bool unicastUpdate;

	// TODO initial entry into the ARP table by gratuitous request or freebsd test==102

	// Checks against 36 format combinations of gratuitous packets to see if the cache is updated
	bool gratuitousUpdates[36];

	ArpFingerprint();
	ArpFingerprint(std::string tinyString);
	std::string toString();
	std::string toTinyString();
	bool operator==(const ArpFingerprint &rhs) const;
	bool operator!=(const ArpFingerprint &rhs) const;
};

struct ResponseBehavior
{
	/* This is true if the host sends a probe reply before sending an ARP packet.
	 This might need to be expanded more though. Linux seems to reply if the ARP entry
	 is in the ARP cache but has become stale, but not if it isn't in the cache at all */
	bool replyBeforeARP;


	/* Was the probe reply to the MAC address we last announced? */
	bool replyToCorrectMAC;

	/* Did we get unicast or multicast requests*/
	/* TODO: Handle the case where we got some combination of both? */
	bool unicastUpdate;

	bool sawProbeReply;

	/* Number of attempts to resolve the ARP address */
	int requestAttempts;

	/* Timing between ARP requests */
	int timeBetweenRequests[MAX_RECORDED_REPLIES];
	double averageTimeBetweenRequests;
	uint32_t m_minTimeBetweenRequests;
	uint32_t m_maxTimebetweenRequests;

	ResponseBehavior()
	{
		m_maxTimebetweenRequests = 0;
		m_minTimeBetweenRequests = ~0;
		requestAttempts = 0;
		sawProbeReply = false;
		averageTimeBetweenRequests = -1;

		for (int i = 0; i < 10; i++)
			timeBetweenRequests[i] = -1;
	}

	// toString that weeds out useless information
	std::string toString()
	{
		std::stringstream ss;
		ss << "Saw reply to probe                            : " << std::boolalpha << sawProbeReply << std::endl;

		if (requestAttempts > 0)
		{
			ss << "Number of ARP Requests Seen                : " << requestAttempts << std::endl;

			if (sawProbeReply) {
				ss << "Replied before ARP request                 : " << std::boolalpha << replyBeforeARP << std::endl;
			}

		}


		if (requestAttempts > 0)
		{
			ss << "Got unicast instead of bcast request        : " << std::boolalpha << unicastUpdate << std::endl;
		}

		if (requestAttempts > 1)
		{
			ss << "Average time between each request (ms)      : " << averageTimeBetweenRequests << std::endl;

			ss << "Time between ARP attempts                   : ";


			for (int i = 0; i < requestAttempts - 1; i++)
			{
				ss << timeBetweenRequests[i] << " ";
			}
			ss << std::endl;

			ss << "Min time between each request (ms)         : " << m_minTimeBetweenRequests << std::endl;
			ss << "Max time between each request (ms)         : " << m_maxTimebetweenRequests << std::endl;
		}

		return ss.str();
	}
};


#endif
