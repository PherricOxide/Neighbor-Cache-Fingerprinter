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
//   along with this software.  If not, see <http://www.gnu.org/licenses/>.
//============================================================================

#include "helpers.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/unistd.h>
#include <net/if.h>
#include <errno.h>

using namespace std;

void addr_pack_eth(addr* addr, uint8_t* eth) {
	addr_pack(addr, ADDR_TYPE_ETH, ETH_ADDR_BITS, eth, ETH_ADDR_LEN);
}

void addr_pack_ip(addr* addr, uint8_t* ip) {
	addr_pack(addr, ADDR_TYPE_IP, IP_ADDR_BITS, ip, IP_ADDR_LEN);
}

addr GetInterfaceIP(const char *dev)
{
	addr invalid;
	invalid.addr_type = ADDR_TYPE_NONE;
	static struct ifreq ifreqs[20];
	struct ifconf ifconf;
	uint  nifaces, i;

	memset(&ifconf,0,sizeof(ifconf));
	ifconf.ifc_buf = (char*) (ifreqs);
	ifconf.ifc_len = sizeof(ifreqs);

	int sock, rval;
	sock = socket(AF_INET,SOCK_STREAM,0);

	if(sock < 0)
	{
		cout << "Error creating socket to check interface IP: "+string(strerror(errno)) << endl;
		return invalid;
	}

	if((rval = ioctl(sock, SIOCGIFCONF , (char*) &ifconf)) < 0 )
	{
		cout << "Error with getLocalIP socket ioctl(SIOGIFCONF): "+string(strerror(errno)) << endl;
		return invalid;
	}

	close(sock);
	nifaces =  ifconf.ifc_len/sizeof(struct ifreq);

	for(i = 0; i < nifaces; i++)
	{
		if(strcmp(ifreqs[i].ifr_name, dev) == 0 )
		{
			char ip_addr [ INET_ADDRSTRLEN ];
			struct sockaddr_in *b = (struct sockaddr_in *) &(ifreqs[i].ifr_addr);

			addr ip;
			addr_pack_ip(&ip, (uint8_t*)&b->sin_addr.s_addr);
			return ip;
		}
	}
	return invalid;
}
