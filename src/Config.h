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

#include <boost/program_options.hpp>
#include <string>
#include <dnet.h>
#include <pthread.h>

#include "Lock.h"

#define CI Config::Inst()
namespace po = boost::program_options;

class Config {
public:
	static Config* Inst();
	void LoadArgs(char** &argv, int &argc);

	pthread_mutex_t configLock;

	std::string m_interface;

	int m_test;

	std::string m_srcipString, m_dstipString;
	std::string m_fingerprintFile;
	addr m_srcip, m_dstip;
	addr m_srcmac, m_inputSrcMac, m_dstmac;
	int m_srcport, m_dstport;
	int m_sleeptime;
	int m_retries;
	int m_probeTimeout;
	std::string m_probeType;

private:
	Config();


	static Config * m_config;

};
