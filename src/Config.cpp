#include "Config.h"
#include <string.h>
#include <stdio.h>

#include <boost/program_options.hpp>

using namespace std;


Config *Config::m_config = NULL;

Config::Config() {};

Config* Config::Inst() {
	if (Config::m_config == NULL)
	{
		Config::m_config = new Config();
	}
	else
	{
		return Config::m_config;
	}
}

void Config::LoadArgs(char ** &argv, int &argc)
{
	cout << "Called loadArgs" << endl;

	po::options_description desc("Allowed options");
	try {
		desc.add_options()
			("help,h", "produce help message")
			("interface,i", 
				po::value<std::string>(&m_interface)->default_value("eth0"),
				"Ethernet interface to use"
			)

			("srcip",
				po::value<std::string>(&m_srcipString)->default_value("192.168.0.42"),
				"Source IP address"
			)
			
			("dstip", 
				po::value<std::string>(&m_dstipString)->default_value("192.168.0.100"),
				"Destination IP address"
			)

			("srcmac", 
				po::value<std::string>()->default_value("BA:BE:BA:BE:CA:FE"),
				"Source MAC Address"
			)
			
			("dstmac",
				po::value<std::string>()->default_value("38:60:77:20:CC:50"),
				"Destination MAC Address"
			)
		;

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help")) {
			cout << desc << endl;
			exit(1);
		}

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

		cout << "Done now " << endl;

	} catch(exception &e)
	{
		cout << "Uncaught exception: " << string(e.what()) << endl;
		cout << endl << desc << endl;
		exit(1);
	}
}




