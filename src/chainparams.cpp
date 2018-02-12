// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        ( 0, uint256("0x2e4b1cd45b62a52132b3fa0bae4f0ae6bd2056b1819c7368b6196e4ee2714414"))
         ;
static const Checkpoints::CCheckpointData data = {
        &mapCheckpoints,
        1518199201, // * UNIX timestamp of last checkpoint block
        0,   // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        750     // * estimated number of transactions per day after checkpoint
    };

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, uint256("0x3c15361db7016401a498e00199a20c6fc29141fcfb059d03fd13b0b86cff869e"))
        ;
static const Checkpoints::CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1518199202,
        0,
        250
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint256("0x93846588b40cb7675888447b8a0b08515174325b073ae380199f564c5234212d"))
        ;
static const Checkpoints::CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        0,
        0,
        0
    };

class CMainParams : public CChainParams {
public:
    CMainParams() {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xc1;
        pchMessageStart[1] = 0xf4;
        pchMessageStart[2] = 0xa7;
        pchMessageStart[3] = 0xd6;

        vAlertPubKey = ParseHex("04cf9f864336158105b71f0a196ee8710c25d08357feb641d1c9e33716434dc0e57bb802972e4b0201dcd8700337c343890b42968b6ee18d6b31202805a52de1e1");
        nDefaultPort = 36003;
        bnProofOfWorkLimit = ~uint256(0) >> 20;
        nSubsidyHalvingInterval = 400000;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 10 * 60; // 10 minutes
        nTargetSpacing = 1 * 60; // 1 minute

        const char* pszTimestamp = "start test dash fork 07/01/2018 22/00";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 120 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("0451c278134675546a1a9375682686279d129e11ce6d0e467da10a34abaa90fa3c7e9d76436db4a56ccedfbb894d94507d8032da373bbda2515214c38e181ba065") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1518199201;
        genesis.nBits    = 0x1e0ffff0;
        genesis.nNonce   = 653326;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x2e4b1cd45b62a52132b3fa0bae4f0ae6bd2056b1819c7368b6196e4ee2714414"));
        assert(genesis.hashMerkleRoot == uint256("0xcdf1190e352155899d5f3138d7b29a1de9c76aea4794730ac8b38e22e1dceefc"));


        base58Prefixes[PUBKEY_ADDRESS] = list_of(56);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(118);
        base58Prefixes[SECRET_KEY] =     list_of(117);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "04fedfacdaaf060e8a65abcba8e4cd323e655670a167956bfb0c1e242428ebad178e691bb3b7a7adcd819d25ea9e70a66574ae25b9484aebc61d90060eed6c9221";
        strMasternodePaymentsPubKey = "04fedfacdaaf060e8a65abcba8e4cd323e655670a167956bfb0c1e242428ebad178e691bb3b7a7adcd819d25ea9e70a66574ae25b9484aebc61d90060eed6c9221";
        strDarksendPoolDummyAddress = "Pq19GqFvajRrEdDHYRKGYjTsQfpV5jyipF";
        nStartMasternodePayments = 1518199201; //Wed, 25 Jun 2014 20:36:16 GMT
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0xd4;
        pchMessageStart[1] = 0xc3;
        pchMessageStart[2] = 0x18;
        pchMessageStart[3] = 0x5e;

        vAlertPubKey = ParseHex("04f71c8bc56e08264367df04fb80a9246ee216ad27347cf1fd285c548b2ea11b341a74051705486b1c6a61545ea131cf8133c8f56236fd6051c353a6ca1daa25fd");
        nDefaultPort = 36005;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 10 * 60; // 10 minutes
        nTargetSpacing = 1 * 60; // 1 minute

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1518199202;
        genesis.nNonce = 2502638;
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x3c15361db7016401a498e00199a20c6fc29141fcfb059d03fd13b0b86cff869e"));

        vFixedSeeds.clear();
        vSeeds.clear();
        

        base58Prefixes[PUBKEY_ADDRESS] = list_of(111);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "042c96df82f3ae57726e29f16f6c254258e32aa013836ed6345457461f2209f337e45502679e8fe72848700a56809bb43088721fc809df009ca437c7af79ff84db";
        strMasternodePaymentsPubKey = "042c96df82f3ae57726e29f16f6c254258e32aa013836ed6345457461f2209f337e45502679e8fe72848700a56809bb43088721fc809df009ca437c7af79ff84db";
        strDarksendPoolDummyAddress = "P1EZuxhhNMAUofTBEeLqGE1bJrpC2TWRNp";
        nStartMasternodePayments = 1518199202; //December 16, 2017 12:00:00 AM GMT+00:00
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xad;
        pchMessageStart[1] = 0xb7;
        pchMessageStart[2] = 0x31;
        pchMessageStart[3] = 0xdf;

        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 10 * 60; // 10 minutes
        nTargetSpacing = 1 * 60; // 1 minute
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1518199203;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 1;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 36007;
        assert(hashGenesisBlock == uint256("0x93846588b40cb7675888447b8a0b08515174325b073ae380199f564c5234212d"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams {
public:
    CUnitTestParams() {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 18445;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const 
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval)  { nSubsidyHalvingInterval=anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority)  { nEnforceBlockUpgradeMajority=anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority)  { nRejectBlockOutdatedMajority=anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority)  { nToCheckBlockUpgradeMajority=anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks)  { fDefaultConsistencyChecks=afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) {  fAllowMinDifficultyBlocks=afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams *pCurrentParams = 0;

CModifiableParams *ModifiableParams()
{
   assert(pCurrentParams);
   assert(pCurrentParams==&unitTestParams);
   return (CModifiableParams*)&unitTestParams;
}

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        case CBaseChainParams::UNITTEST:
            return unitTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
