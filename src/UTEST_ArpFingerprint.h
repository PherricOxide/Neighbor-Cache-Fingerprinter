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
	foo.requestAttempts = 42;
	foo.constantRetryTime = true;
	foo.gratuitousUpdates[3] = true;
	foo.gratuitousUpdates[2] = false;
	foo.unicastUpdate = false;
	foo.replyBeforeUpdate = true;
	foo.referencedStaleTimeout = 108;

	ArpFingerprint copy = ArpFingerprint(foo.toTinyString());

	EXPECT_EQ(foo, copy);
	EXPECT_EQ(foo.toTinyString(), copy.toTinyString());
}
