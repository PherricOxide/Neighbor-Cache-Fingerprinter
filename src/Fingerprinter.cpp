#include "Fingerprinter.h"
#include "Config.h"

#include <iostream>
#include <fstream>
#include <string>
#include <utility>
#include <math.h>

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
				//cout << "Loaded in " << fingerprint.toTinyString() << endl;
			}
		}
		fingerprintFile.close();
	} else {
		cout << "Unable to open fingerprint file at " << CI->m_fingerprintFile << endl;
	}
}

int Fingerprinter::CompareFingerprints(ArpFingerprint f1, ArpFingerprint f2) {
	cout << "Comparison," << endl;
	cout << f1.toTinyString()<< endl;
	cout << f2.toTinyString() << endl;
	cout << endl;
	int differenceScore = 0;
	if (f1.requestAttempts != f2.requestAttempts)
		differenceScore += 5;

	if (f1.constantRetryTime != f2.constantRetryTime)
		differenceScore += 2;

	if (f1.referencedStaleTimeout != f2.referencedStaleTimeout) {
		if (abs(f1.referencedStaleTimeout - f2.referencedStaleTimeout) > 5) {
			differenceScore += 2;
		}
	}

	if (f1.replyBeforeUpdate != f2.replyBeforeUpdate)
		differenceScore += 2;

	if (f1.unicastUpdate != f2.unicastUpdate)
		differenceScore += 2;

	for (int i = 0; i < 36; i++) {
		if (f1.gratuitousUpdates[i] != f2.gratuitousUpdates[i]) {
			differenceScore += 1;
		}
	}

	return differenceScore;
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

	// TODO sort the results

	for (uint i = 0; i < results.size(); i++) {
		cout << results[i].first << "\t\t" << results[i].second << endl;
	}

	return "";
}
