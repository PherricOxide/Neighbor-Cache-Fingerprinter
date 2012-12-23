#include <boost/program_options.hpp>
#include <string>
#include <dumbnet.h>

#define CI Config::Inst()
namespace po = boost::program_options;

class Config {
public:
	static Config* Inst();
	void LoadArgs(char** &argv, int &argc);


	std::string m_interface;

	int m_test;

	std::string m_srcipString, m_dstipString;
	addr m_srcip, m_dstip;
	addr m_srcmac, m_dstmac;
	int m_srcport, m_dstport;
	int m_sleeptime;
	int m_retries;
private:
	Config();


	static Config * m_config;

};
