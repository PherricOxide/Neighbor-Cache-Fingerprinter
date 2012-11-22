#include <iostream>


#include "InterfacePacketCapture.h"

using namespace std;
using namespace Nova;

void cb(unsigned char *index, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
	cout << "Got packet " << endl;
}


int main()
{
	InterfacePacketCapture *capture = new InterfacePacketCapture("eth0");
	capture->Init();
	capture->SetPacketCb(&cb);
	capture->StartCaptureBlocking();	
	
	return 0;
}


