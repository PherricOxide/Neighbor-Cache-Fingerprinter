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
			lineNumber++;

			if (line == "" || line == " ") {
				continue;
			}

			if (lineNumber % 2 != 0) {
				fingerprintName = line;
				continue;
			} else {
				ArpFingerprint fingerprint(line);
				fingerprint.name = fingerprintName;
				m_fingerprints.push_back(fingerprint);
				//cout << "Loading   " << line << endl;
				//cout << "Loaded in " << fingerprint.toTinyString() << endl << endl;
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
