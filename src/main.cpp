#include <iostream>
#include <dumbnet.h>
#include <cstring>

#include "InterfacePacketCapture.h"

using namespace std;
using namespace Nova;

// TODO: Don't hard code this
#define INTERFACE "wlan0"

void cb(unsigned char *index, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
	cout << "Got packet " << endl;
}

void SendSYN(
		addr dstIP, addr dstMAC,
		addr srcIP, addr srcMAC,
		int dstPort, int srcPort)
{

	int bufferSize = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + TCP_OPT_LEN + 2;
	unsigned char buffer[bufferSize];

	eth_pack_hdr(buffer, dstMAC.addr_eth, srcMAC.addr_eth, ETH_TYPE_IP);
	ip_pack_hdr(buffer + ETH_HDR_LEN, 0, IP_HDR_LEN + TCP_HDR_LEN + 4, 0, 0, 128, IP_PROTO_TCP, srcIP.addr_ip, dstIP.addr_ip);
	tcp_pack_hdr(buffer + ETH_HDR_LEN + IP_HDR_LEN, srcPort, dstPort, 0x42, 0, TH_SYN, 4096, 0);


	tcp_hdr *hdr = (tcp_hdr*)(buffer + ETH_HDR_LEN + IP_HDR_LEN);
	hdr->th_off = 6;

	tcp_opt *opt = (tcp_opt*)(buffer + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
	opt->opt_type = TCP_OPT_MSS;
	opt->opt_len = 4;
	opt->opt_data.mss = 1460;

	ip_checksum(buffer + ETH_HDR_LEN, bufferSize - ETH_HDR_LEN);
	eth_t *eth = eth_open(INTERFACE);
	if (eth == NULL)
	{
		cout << "Unable to open ethernet interface to send TCP SYN" << endl;
		return;
	}

	eth_send(eth, buffer, bufferSize);
	eth_close(eth);
}

int main()
{
	addr dstMac, dstIp, srcMac, srcIp;
	unsigned char dstEthData[ETH_ADDR_LEN] = {0xa8, 0x39, 0x44, 0x5d, 0x18, 0x24};
	addr_pack(&dstMac, ADDR_TYPE_ETH, ETH_ADDR_BITS, dstEthData, ETH_ADDR_LEN);

	unsigned char srcEthData[ETH_ADDR_LEN] = {0xa8, 0x39, 0x44, 0x44, 0x55, 0x66};
	addr_pack(&srcMac, ADDR_TYPE_ETH, ETH_ADDR_BITS, srcEthData, ETH_ADDR_LEN);

	addr_pton( "192.168.0.13", &dstIp);
	addr_pton("192.168.0.337", &srcIp);

	SendSYN(dstIp, dstMac, srcIp, srcMac, 42, 42);
	return 0;

	InterfacePacketCapture *capture = new InterfacePacketCapture(INTERFACE);
	capture->Init();
	capture->SetPacketCb(&cb);
	capture->StartCaptureBlocking();	
	


	return 0;
}


