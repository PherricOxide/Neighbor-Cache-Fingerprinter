#include "ArpFingerprint.h"

using namespace std;

ArpFingerprint::ArpFingerprint() {
		unicastUpdate = false;
		replyBeforeUpdate = false;
		requestAttempts = 0;

		for (int i = 0; i < 36; i++)
			gratuitousUpdates[i] = false;
}

std::string ArpFingerprint::toString()
{
	std::stringstream ss;
	ss << "Number of ARP Requests Seen                : " << requestAttempts << std::endl;
	ss << "Constant retry between attempts            : " << std::boolalpha << constantRetryTime << std::endl;
	ss << "Stale timeout value                        : " << referencedStaleTimeout << std::endl;
	ss << "Replied before ARP request                 : " << std::boolalpha << replyBeforeUpdate << std::endl;
	ss << "Got unicast instead of bcast request       : " << std::boolalpha << unicastUpdate << std::endl;

	ss << "Gratuitous probe result fingerprint        : ";
	for (int i = 0; i < 36; i++)
	{
		if (gratuitousUpdates[i]) {
			ss << "1";
		} else {
			ss << "0";
		}
	}

	ss << std::endl;

	return ss.str();
}
