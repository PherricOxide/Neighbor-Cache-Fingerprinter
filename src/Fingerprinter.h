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
