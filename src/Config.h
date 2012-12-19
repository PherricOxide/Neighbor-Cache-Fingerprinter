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
	
	std::string m_srcipString;
	addr m_srcip;

	std::string m_dstipString;
	addr m_dstip;

	addr m_srcmac;
	addr m_dstmac;
	
private:
	Config();


	static Config * m_config;

};
