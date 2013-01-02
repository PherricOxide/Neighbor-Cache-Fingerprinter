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

#include "Fingerprinter.h"
#include "Config.h"

#include <iostream>
#include <fstream>
#include <string>
#include <utility>
#include <math.h>
#include <algorithm>

using namespace std;

Fingerprinter::Fingerprinter() {}

void Fingerprinter::LoadFingerprints() {
	string line;
	string fingerprintName;
	ifstream fingerprintFile (CI->m_fingerprintFile.c_str());
	int lineNumber = 0;
	if (fingerprintFile.is_open()) {
		while ( fingerprintFile.good() ) {
			getline (fingerprintFile,line);
			// Skip past comment lines
			if (line.size() > 0 && line.at(0) == '#')
				continue;

			// Skip past empty lines
			if (line == "" || line == " ")
				continue;

			lineNumber++;


			if (lineNumber % 2 != 0) {
				fingerprintName = line;
				continue;
			} else {
				ArpFingerprint fingerprint(line);
				fingerprint.name = fingerprintName;
				m_fingerprints.push_back(fingerprint);
				//cout << "Loading   " << fingerprintName << endl << line << endl;
				//cout << "Loaded in " << fingerprint.toString() << endl << endl;

				if (line != fingerprint.toTinyString())
					cout << "Possible error reading fingerprint for " << fingerprintName << endl;
			}
		}
		fingerprintFile.close();
	} else {
		cout << "Unable to open fingerprint file at " << CI->m_fingerprintFile << endl;
	}
}

int Fingerprinter::CompareFingerprints(ArpFingerprint f1, ArpFingerprint f2) {
	//cout << "Comparison," << endl;
	//cout << f1.toTinyString()<< endl;
	//cout << f2.toTinyString() << endl;
	//cout << endl;

	// These differenceScore numbers are mostly arbitrary, there needs to
	// be some more experimenting done to tweak them to maximize accuracy
	int differenceScore = 0;
	if (f1.requestAttemptsMin != f2.requestAttemptsMin)
		differenceScore += 8;

	if (f1.requestAttemptsMax != f2.requestAttemptsMax)
		differenceScore += 8;

	if (f1.constantRetryTime != f2.constantRetryTime)
		differenceScore += 4;

	if (f1.referencedStaleTimeout != f2.referencedStaleTimeout) {
		if (abs(f1.referencedStaleTimeout - f2.referencedStaleTimeout) > 5) {
			differenceScore += 4;
		}
	}

	if (abs(f1.minTimeBetweenRetries - f2.minTimeBetweenRetries) > 250000)
		differenceScore += 4;

	if (abs(f1.maxTimeBetweenRetries - f2.maxTimeBetweenRetries) > 250000)
		differenceScore += 4;

	if (f1.replyBeforeUpdate != f2.replyBeforeUpdate)
		differenceScore += 4;

	if (f1.unicastUpdate != f2.unicastUpdate)
		differenceScore += 4;

	if (f1.gratuitousReplyAddsCacheEntry != f2.gratuitousReplyAddsCacheEntry)
		differenceScore += 4;

	if (f1.hasFloodProtection != f2.hasFloodProtection)
		differenceScore += 4;

	if (f1.correctARPProbeResponse  != f2.correctARPProbeResponse)
		differenceScore += 6;

	for (int i = 0; i < 36; i++) {
		if (f1.gratuitousUpdates[i] != f2.gratuitousUpdates[i]) {
			differenceScore += 1;
		}
	}

	return differenceScore;
}

bool compareFunction(pair<int, string> a, pair<int, string> b) {
	return a.first < b.first;
}

std::string Fingerprinter::GetMatchReport(ArpFingerprint fingerprint) {
	vector<pair<int, string> > results;
	for(uint i = 0; i < m_fingerprints.size(); i++) {
		int diff = CompareFingerprints(fingerprint, m_fingerprints[i]);
		pair<int, string> comparison;
		comparison.first = diff;
		comparison.second = m_fingerprints[i].name;
		results.push_back(comparison);
	}

	sort(results.begin(), results.end(), compareFunction);

	for (uint i = 0; i < results.size(); i++) {
		cout << results[i].first << "\t\t" << results[i].second << endl;
	}

	return "";
}
