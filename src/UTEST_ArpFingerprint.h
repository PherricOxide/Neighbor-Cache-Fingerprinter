//============================================================================
// Name        : ArpFingerprint.h
// Copyright   : David Clark (PherricOxide) 2011-2012
// Description : This file contains unit tests for the class ArpFingerprint
//============================================================================/*

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
	foo.hasFloodProtection = true;
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
