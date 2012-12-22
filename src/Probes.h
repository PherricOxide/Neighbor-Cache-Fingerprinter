#include <dumbnet.h>
#include <pthread.h>

class Prober {
public:
	/* Buffer for our probe packets */
	static const int probeBufferSize = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
	unsigned char probeBuffer[probeBufferSize];
	pthread_mutex_t probeBufferLock;

	Prober();

	void SendARPReply(struct addr *srcMAC, struct addr *dstMAC, struct addr *srcIP, struct addr *dstIP);

	void SendSYN(
			addr dstIP, addr dstMAC,
			addr srcIP, addr srcMAC,
			int dstPort, int srcPort);

};
