#ifndef FINGERPRINTER_H
#define FINGERPRINTER_H

#include "ArpFingerprint.h"

#include <vector>

class Fingerprinter {
public:
	Fingerprinter();

	void LoadFingerprints();
	std::string GetMatchReport(ArpFingerprint fingerprint);

private:
	// Returns an integer value representing closeness (lower is better, 0 is equal)
	int CompareFingerprints(ArpFingerprint f1, ArpFingerprint f2);

	std::vector<ArpFingerprint> m_fingerprints;
};

#endif
