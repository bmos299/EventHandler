//Import Hyperledger Fabric 1.4 programming model - fabric-network
'use strict';

const { FileSystemWallet, Gateway, X509WalletMixin } = require('fabric-network');
const path = require('path');
const fs = require('fs');
const uuidv1 = require('uuid/v1');
const hasha = require('hasha');

//connect to the config file
const configPathPrefix = path.join(process.cwd(), 'config');
const configPath = path.join(configPathPrefix, 'config.json');
const configJSON = fs.readFileSync(configPath, 'utf8');
const config = JSON.parse(configJSON);

const gatewayDiscovery = config.gatewayDiscovery;
const appAdmin = config.appAdmin;
const channelName = config.channel_name;
const smartContractName = config.smart_contract_name;

const connectionProfiles = {};
const supportedOrgs = ['Org1', 'Org2']; 

// Get connection profiles for each org
supportedOrgs.forEach(orgName => {
    const ccpPath = path.join(configPathPrefix, config[orgName].connection_file);
    const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
    const ccpForOrg = JSON.parse(ccpJSON);
    connectionProfiles[orgName] = ccpForOrg;    
});

exports.supportedOrgs = supportedOrgs;

//connect to the blockchain network using username
exports.connectToNetwork = async function(orgName = 'Org1') {
    console.log(`ENTER: connectToNetwork ${orgName}`)

    const walletPathPrefix = path.join(process.cwd(), `_idwallet_${orgName}` );
    let peerAddr = config[orgName].peerName;
    let ccp = connectionProfiles[orgName];

    const gateway = new Gateway();
    try {
        const walletPath = path.join(walletPathPrefix);
        const wallet = new FileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the admin user.
        const adminExists = await wallet.exists(appAdmin);
        if (!adminExists) {
            console.error(`An identity for the admin user ${appAdmin} does not exist in the wallet`);
            console.log('Run the enrollAdmin.js application before retrying');
            let response = {};
            response.err = `An identity for the admin user ${appAdmin} does not exist in the wallet. 
              Run the enrollAdmin.js application before retrying`;
            return response;
        }

        await gateway.connect(ccp, { wallet, identity: appAdmin, discovery: gatewayDiscovery });

        const network = await gateway.getNetwork(channelName);
        const contract = await network.getContract(smartContractName);
        const client = gateway.getClient();
        const channel = client.getChannel(channelName);
        let event_hub = channel.newChannelEventHub(peerAddr);

        let networkObj = {
            contract: contract,
            network: network,
            gateway: gateway,
            event_hub: event_hub
        };
        return networkObj;

    } catch (error) {
        console.log(`Error processing transaction. ${error}`);
        console.error(error.stack);
        let response = {};
        response.err = error;
        return response;
    } finally {
        console.log('Done connecting to network.');
    }
};


//get list of AITrust Assets owned by emailAddress
exports.queryAITrustAssetsByType = async function(networkObj, assetType) {
    try {
        let response = await networkObj.contract.evaluateTransaction('queryAllAITrustAssetsByType', assetType);
        return response;
    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        return error;
    } finally {
        await networkObj.gateway.disconnect();
    }
};

//get list of AITrust Assets owned by emailAddress
exports.queryAITrustAssetsByOwner = async function(networkObj, assetType, assetOwner) {
    console.log('Entered queryAITrustAssetsByOwner');
    try {
        let response = await networkObj.contract.evaluateTransaction('queryAITrustAssetsByOwner', assetType, assetOwner);
        return response;
    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        return error;
    } finally {
        await networkObj.gateway.disconnect();
    }
};

//get the hash of an asset
exports.getHashFromAsset = async function(asset) {
    //console.log('Calculating hash from asset');
    let hashOutput = hasha(asset);
    //console.log(`The MD5 sum of the file is: ${hashOutput}`);
    return hashOutput;
};

//read AITrust Asset by assetId
exports.readAITrustAsset = async function(networkObj, assetId) {
    try {
        let response = await networkObj.contract.evaluateTransaction('readAITrustAsset', assetId);
        return response;
    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        return error;
    } finally {
        await networkObj.gateway.disconnect();
    }
};

//create a new AITrust Asset object
exports.createAITrustAsset = async function(networkObj, assetType, propertyHashes, propertyValues, lineageInfo, otherInfo) {
    try {
        //Generate asset ID
        let assetUUID = uuidv1();
        //submit transaction 
        let response = await networkObj.contract.submitTransaction('createAITrustAsset', assetType, assetUUID, 
            propertyHashes, propertyValues, lineageInfo, otherInfo);
        return response;
    } catch (error) {
        console.error(`Failed to submit transaction: ${error}`);
        return error;
    } finally {
        await networkObj.gateway.disconnect();
    }
};

exports.updateAITrustAsset = async function(networkObj, assetUUID, propertyHashes, propertyValues, lineageInfo, otherInfo) {
    try {
        let response =  await networkObj.contract.submitTransaction('updateAITrustAsset', assetUUID, 
        propertyHashes, propertyValues, lineageInfo, otherInfo);
        return response;
    } catch (error) {
        console.error(`Failed to submit transaction: ${error}`);
        return error;
    } finally {
        await networkObj.gateway.disconnect();
    }
};


//delete a AITrust Asset
exports.deleteAITrustAsset = async function(networkObj, assetId) {
    try {
        let response = await networkObj.contract.submitTransaction('deleteAITrustAsset', assetId);
        return response;
    } catch (error) {
        console.error(`Failed to submit transaction: ${error}`);
        return error;
    } finally {
        await networkObj.gateway.disconnect();
    }
};

exports.getHistoryForAITrustAsset = async function(assetId) {
    let response = {};
    if (!assetId) {
        console.error('Error - no assetId found');
        response.err = 'Error - no assetId found';
    } else {
        let networkObj = await this.connectToNetwork();
        response = await networkObj.contract.evaluateTransaction('getHistoryForAITrustAsset', assetId);
    }
    return response;
};
