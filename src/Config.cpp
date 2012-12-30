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

#include "Config.h"
#include <string.h>
#include <stdio.h>

#include <boost/program_options.hpp>

using namespace std;


Config *Config::m_config = NULL;

Config::Config() {};

Config* Config::Inst() {
	if (Config::m_config == NULL) {
		Config::m_config = new Config();
	} else {
		return Config::m_config;
	}
}

void Config::LoadArgs(char ** &argv, int &argc) {
	po::options_description desc("Allowed options");
	try {
		string testString = "Test to run, \n";
		testString += "0: Generate Fingerprint.\n";
		testString += "The following are partial fingerprint tests for advanced users,\n";
		testString += "1: Probe with no reply.\n";
		testString += "2: Probe reply then check timeout.\n";
		testString += "3: Check response to gratuitous ARP.\n";
		testString += "4: Check response to different gratuitous ARP packet types.\n";
		testString += "5: Check for ARP REPLY flood protection.\n";
		testString += "6: Try to find exact ARP REPLY flood protection timing.\n";
		testString += "7: Send gratuitous ARP and check if in table.\n";
		testString += "8: Check behavior on RFC5227 ARP Probe.\n";

		desc.add_options()
			("help,h", "produce help message")
			("interface,i", 
				po::value<std::string>(&m_interface)->default_value("eth0"),
				"Ethernet interface to use"
			)

			("srcip",
				po::value<std::string>(&m_srcipString)->required(),
				"Source IP address"
			)
			
			("dstip", 
				po::value<std::string>(&m_dstipString)->required(),
				"Destination IP address"
			)

			("srcmac", 
				po::value<std::string>()->default_value("BA:BE:CA:FE:00:00"),
				"Source MAC Address"
			)
			
			("dstmac",
				po::value<std::string>()->default_value("00:00:00:00:00:00"),
				"Destination MAC Address"
			)

			("srcport",
					po::value<int>(&m_srcport)->default_value(42),
					"Source Port"
			)

			("dstport",
					po::value<int>(&m_dstport)->default_value(333),
					"Destination Port"
			)

			("wait",
					po::value<int>(&m_sleeptime)->default_value(8),
					"How long to wait for replies before assumed server has given up"
			)

			("test",
					po::value<int>(&m_test)->default_value(0),
					testString.c_str()
			)

			("retries",
					po::value<int>(&m_retries)->default_value(3),
					"Depends on --test value"

			)

			("fingerprints",
					po::value<string>(&m_fingerprintFile)->default_value("fingerprints.txt"),
					"Path to the fingerprints file"
			)

		;

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);

		if (vm.count("help")) {
			cout << "Usage: neighbor-fingerprint --dstip x.x.x.x --srcip x.x.x.x" << endl;
			cout << "srcip should be an UNUSED IP address to spoof. It must not be in the ARP cache of the machine being targeted." << endl << endl;
			cout << desc << endl;
			exit(1);
		}
		po::notify(vm);

		addr_pton(vm["srcip"].as<string>().c_str(), &m_srcip);
		addr_pton(vm["dstip"].as<string>().c_str(), &m_dstip);

		if (vm.count("srcmac")) {
			unsigned int d0,d1,d2,d3,d4,d5;

			sscanf(vm["srcmac"].as<string>().c_str(), "%x:%x:%x:%x:%x:%x", &d0,&d1,&d2,&d3,&d4,&d5);
			
			unsigned char srcMac[ETH_ADDR_LEN];
			srcMac[0] = (uint8_t)d0;
			srcMac[1] = (uint8_t)d1;
			srcMac[2] = (uint8_t)d2;
			srcMac[3] = (uint8_t)d3;
			srcMac[4] = (uint8_t)d4;
			srcMac[5] = (uint8_t)d5;
			
			addr_pack(&m_srcmac, ADDR_TYPE_ETH, ETH_ADDR_BITS, srcMac, ETH_ADDR_LEN);
		}
	
		if (vm.count("dstmac")) {
			unsigned int d0,d1,d2,d3,d4,d5;

			sscanf(vm["dstmac"].as<string>().c_str(), "%x:%x:%x:%x:%x:%x", &d0,&d1,&d2,&d3,&d4,&d5);
			
			unsigned char dstMac[ETH_ADDR_LEN];
			dstMac[0] = (uint8_t)d0;
			dstMac[1] = (uint8_t)d1;
			dstMac[2] = (uint8_t)d2;
			dstMac[3] = (uint8_t)d3;
			dstMac[4] = (uint8_t)d4;
			dstMac[5] = (uint8_t)d5;
			
			addr_pack(&m_dstmac, ADDR_TYPE_ETH, ETH_ADDR_BITS, dstMac, ETH_ADDR_LEN);
		}

	} catch(exception &e) {
		cout << "Uncaught exception: " << string(e.what()) << endl;
		cout << endl << desc << endl;
		exit(1);
	}
}
