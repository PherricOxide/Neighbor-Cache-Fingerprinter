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

#include "gtest/gtest.h"

#include "ArpFingerprint.h"

using namespace std;

// The test fixture for testing class ArpFingerprint.
class ArpFingerprintTest : public ::testing::Test {
protected:
	ArpFingerprint testObject;

	virtual void SetUp() {
	}
};

TEST_F(ArpFingerprintTest, test_tinyStringification)
{
	ArpFingerprint foo;
	foo.requestAttemptsMin = 1;
	foo.requestAttemptsMax = 3;
	foo.constantRetryTime = true;
	foo.gratuitousReplyAddsCacheEntry = true;
	foo.hasFloodProtection = false;
	foo.correctARPProbeResponse  = true;
	for (int i = 0; i < 36; i++)
	{
		if (i %2 == 0)
			foo.gratuitousUpdates[i] = false;
		else
			foo.gratuitousUpdates[i] = true;
	}
	foo.unicastUpdate = false;
	foo.replyBeforeUpdate = true;
	foo.referencedStaleTimeout = 108;

	ArpFingerprint copy = ArpFingerprint(foo.toTinyString());

	EXPECT_EQ(foo, copy);
	EXPECT_EQ(foo.toTinyString(), copy.toTinyString());
}
