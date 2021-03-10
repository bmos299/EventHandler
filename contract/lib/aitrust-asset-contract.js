/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { Contract } = require('fabric-contract-api');
//import files containing constructors
const AITrustAsset = require('./AITrustAsset.js');
const ModificationPendingApproval = require('./ModificationPendingApproval.js');
const User = require('./User.js');

class AITrustAssetContract extends Contract {
    constructor(){
        super('AITrustAssetContract');
    }

    /**
     * aitrustAssetExists
     *
     * This function checks if a AITrustAsset exists in the blockchain.
     *
     * @param {Context} ctx - The context of the transaction.
     * @param {String} assetUUID - Identifier for the aitrust asset.
     * @returns - true if the asset exists and false if the asset does not exist.
     */
    async aitrustAssetExists(ctx, assetUUID) {
        const buffer = await ctx.stub.getState(assetUUID);
        return (!!buffer && buffer.length > 0);
    }

    /**
     *
     * createAITrustAsset
     *
     * This function creates a new AITrustAsset.
     *
     * @param {Context} ctx - The context of the transaction.
     * @param {String} assetType - Type of aitrust asset.
     * @param {String} assetUUID - Unique identifier of the aitrust asset.
     * @param {Map} assetHashes - Hashmap with hashes for aitrust asset properties.
     * @param {Map} plainTextContent - Hashmap with attribute values.
     * @param {Object} lineageInfo - aitrust asset lineage info
     * @param {Array} otherInfo - additional information on this asset
     * @returns - nothing - but creates a AITrustAsset object and updates the world state with the AITrustAsset.
     */
    async createAITrustAsset(ctx, assetType, assetUUID, assetHashes, plainTextContent, lineageInfo, otherInfo) {
        console.info("Enter: createAITrustAsset");
        let response = {};
        let assetExist = await this.aitrustAssetExists(ctx, assetUUID);
        if (assetExist) {
            //asset with this hash exists. Return with error msg.
            response.err = `AITrust asset ${assetUUID} already exists`;
            return response;
        }
        //asset with this hash does not exist, can go ahead and create the asset.
        let owner = ctx.stub.getCreator().mspid;
        console.info(`Asset Owner: ${owner}`);

        let aitrustAsset = new AITrustAsset(assetType, assetUUID, JSON.parse(assetHashes), JSON.parse(plainTextContent), 
            JSON.parse(lineageInfo), JSON.parse(otherInfo), ctx.stub.getCreator().mspid);
        await ctx.stub.putState(assetUUID, Buffer.from(JSON.stringify(aitrustAsset)));

        // define and set createAITrustAssetEvent
        let createAITrustAssetEvent = {
            type: 'Create AITrust Asset',
            assetType: assetType,
            assetUUID: assetUUID,
            assetHashes: assetHashes,
            plainTextContent: plainTextContent,
            lineageInfo: lineageInfo,
            otherInfo: otherInfo,
            assetOwner: owner
        };
        ctx.stub.setEvent('CreateAITrustAssetEvent-'+assetUUID, Buffer.from(JSON.stringify(createAITrustAssetEvent)));
        
        //let's return the asset that was just created.
        response = aitrustAsset;
        return response;
    }

    /**
     *
     * readAITrustAsset
     *
     * This function reads and returns the asset identified by assetId.
     *
     * @param {Context} ctx - the context of the transaction.
     * @param {String} assetUUID - Identifier for the aitrust asset.
     * @returns - the asset in JSON object form, if it exists, otherwise it throws an error
     */
    async readAITrustAsset(ctx, assetUUID) {
        console.log("Enter: readDigialAsset");
        let response = {};
        let exists = await this.aitrustAssetExists(ctx, assetUUID);
        if (!exists) {
            response.err = `The AITrust Asset ${assetUUID} does not exist`;
            return response;
        }

        let buffer = await ctx.stub.getState(assetUUID);
        response = JSON.parse(buffer.toString());

        return response;
    }

    /**
     *
     * updateAITrustAsset
     *
     * This function updates an existing AITrustAsset.
     *
     * @param {Context} ctx - the context of the transaction.
     * @param {String} assetUUID - Identifier for the aitrust asset.
     * @param {String} assetHashes - Hash of the aitrust asset.
     * @param {String} lastModifiedBy - Email address of the user who last modified the asset.
     * @returns - nothing - but updates the world state with the AITrustAsset.
     */
    async updateAITrustAsset(ctx, assetUUID, assetHashes, plainTextContent, lineageInfo, otherInfo) {
        console.info("Enter: updateDigialAsset");

        let exists = await this.aitrustAssetExists(ctx, assetUUID);
        if (!exists) {
            response.err = `The AITrust Asset ${assetUUID} does not exist`;
            return response;
        }

        let readResponse = await this.readAITrustAsset(ctx, assetUUID);
        let aitrustAsset = readResponse;
        let updateAITrustAssetEvent = {
            type: 'Update AITrust Asset',
            assetUUID: assetUUID
        };

        assetHashes = JSON.parse(assetHashes);
        if(assetHashes){
            aitrustAsset.assetHashes = assetHashes;
            updateAITrustAssetEvent.assetHashes = assetHashes;
        }
        plainTextContent = JSON.parse(plainTextContent);
        if(plainTextContent){
            aitrustAsset.plainTextContent = plainTextContent;
            updateAITrustAssetEvent.plainTextContent = plainTextContent;
        }
        lineageInfo = JSON.parse(lineageInfo);
        if(lineageInfo) {
            let lineageInfoChanges = {};
            if(typeof lineageInfo.sourceAssets !== 'undefined' && lineageInfo.sourceAssets !== null){
                aitrustAsset.lineageInfo.sourceAssets = lineageInfo.sourceAssets;
                lineageInfoChanges.sourceAssets = lineageInfo.sourceAssets;
            }
            if(typeof lineageInfo.transformationType !== 'undefined' && lineageInfo.transformationType !== null) {
                aitrustAsset.lineageInfo.transformationType = lineageInfo.transformationType;
                lineageInfoChanges.transformationType = lineageInfo.transformationType;
            }
            if(typeof lineageInfo.transformationInfo !== 'undefined' && lineageInfo.transformationInfo !== null){
                aitrustAsset.lineageInfo.transformationInfo = lineageInfo.transformationInfo;
                lineageInfoChanges.transformationInfo = lineageInfo.transformationInfo;
            }

            updateAITrustAssetEvent.lineageInfo = lineageInfoChanges;
        }
        otherInfo = JSON.parse(otherInfo);
        if(otherInfo) {
            aitrustAsset.otherInfo = otherInfo;
            updateAITrustAssetEvent.otherInfo = otherInfo;
        }

        await ctx.stub.putState(assetUUID, Buffer.from(JSON.stringify(aitrustAsset)));
        
        ctx.stub.setEvent('UpdateAITrustAssetEvent-'+assetUUID, Buffer.from(JSON.stringify(updateAITrustAssetEvent)));

        //let's return the full object with all changes
        return aitrustAsset;
    }

    /**
     *
     * deleteAITrustAsset
     *
     * This function marks an existing AITrust Asset from the blockchain as deleted.
     *
     * @param {Context} ctx - the context of the transaction.
     * @param {String} assetUUID - Identifier for the aitrust asset.
     * @returns - nothing - but marks the AITrust Asset as "deleted" in the world state if the asset exists and the assetDeleter is the same as the assetOwner, else throws an error.
     */
    async deleteAITrustAsset(ctx, assetUUID) {
        console.info("Enter: deleteAITrustAsset");
        let response = {};
        let exists = await this.aitrustAssetExists(ctx, assetUUID);
        
        if (!exists) {
            response.err = `The AITrust Asset ${assetUUID} does not exist`;
            return response;
        }


        let readResponse = await this.readAITrustAsset(ctx, assetUUID);
        let aitrustAsset = readResponse;

        let callerMSP = ctx.stub.getCreator().mspid;
        console.info(`Caller MSP: ${callerMSP}`);

        if(aitrustAsset.assetOwner !== callerMSP){
            response.err = `AITrust assets can only be deleted by the owner of the asset.  Owner organization is ${aitrustAsset.assetOwner} but caller org is ${callerMSP}`;
            return response;
        }

        await ctx.stub.deleteState(assetUUID);

        // define and set deleteAITrustAssetEvent
        let deleteAITrustAssetEvent = {
            type: 'Delete AITrust Asset',
            assetUUID: assetUUID,
            assetOwner: aitrustAsset.assetOwner
        };
        ctx.stub.setEvent('DeleteAITrustAssetEvent-'+assetUUID, Buffer.from(JSON.stringify(deleteAITrustAssetEvent)));

        //let's return the object that was deleted
        return aitrustAsset;
    }


    /**
     *
     * queryAllAITrustAssets
     *
     * Query and return all key value pairs representing aitrust assets in the world state
     *
     * @param {Context} ctx the transaction context
     * @param {String} assetType - Type of aitrust asset.
     * @returns - all key value pairs representing aitrust assets in the world state
     */
    async queryAllAITrustAssetsByType(ctx, assetType) {
        console.info("Enter: queryAllAITrustAssetsByType");
        let response = {};

        let queryString = {
            selector: {
                assetType: assetType
            },
            use_index: ['_design/typeIndexDoc', 'typeIndex']
        };

        response = await this.queryWithQueryString(ctx, JSON.stringify(queryString));
        return response;
    }

    /**
     *
     * queryAITrustAssetsByOwner
     *
     * Query and return all key value pairs representing aitrust assets in the world state that have assetOwner = emailAddress
     *
     * @param {Context} ctx the transaction context
     * @param {String} assetType - Type of aitrust asset.
     * @param {String} assetOwner - Owner organization
     * @returns - all key value pairs representing aitrust assets in the world state that have assetOwner = emailAddress
     */
    async queryAITrustAssetsByOwner(ctx, assetType, assetOwner) {
        console.info("Enter: queryAITrustAssetsByOwner");
        let response = {};

        let queryString = {
            selector: {
                assetType: assetType,
                assetOwner: assetOwner
            },
            use_index: ['_design/typeAndAssetOwnerIndexDoc', 'typeAndAssetOwnerIndex']
        };

        response = await this.queryWithQueryString(ctx, JSON.stringify(queryString));
        return response;
    }

    /**
     *
     * queryWithQueryString
     *
     * Evaluate a queryString
     *
     * @param {Context} ctx the transaction context
     * @param {String} queryString the query string to be evaluated
     *
     * @returns - the result of the query string
    */
    async queryWithQueryString(ctx, queryString) {
        console.info("Enter: queryWithQueryString");
        let resultsIterator = await ctx.stub.getQueryResult(queryString);

        let allResults = [];

        // eslint-disable-next-line no-constant-condition
        while (true) {
            let res = await resultsIterator.next();

            if (res.value && res.value.value.toString()) {
                let jsonRes = {};

                jsonRes.Key = res.value.key;

                try {
                    jsonRes.Record = JSON.parse(res.value.value.toString('utf8'));
                } catch (err) {
                    console.log(err);
                    jsonRes.Record = res.value.value.toString('utf8');
                }

                allResults.push(jsonRes);
            }
            if (res.done) {
                await resultsIterator.close();
                return allResults;
            }
        }
    }

    /**
     *
     * getHistoryForAITrustAsset
     *
     * Get the modification history for a aitrust asset.
     *
     * @param {Context} ctx - the context of the transaction.
     * @param {String} assetUUID - Identifier for the aitrust asset.
     *
     * @returns - the entire hisgtroy of the given asset identified by assetId.
    */
    async getHistoryForAITrustAsset(ctx, assetUUID) {
        console.info("Enter: getHistoryForAITrustAsset");
        console.info('- start getHistoryForAITrustAsset: %s\n', assetUUID);

        let resultsIterator = await ctx.stub.getHistoryForKey(assetUUID);
        let allResults = [];

        let index = 0;
        // eslint-disable-next-line no-constant-condition
        while (true) {
            let res = await resultsIterator.next();

            if (res.value && res.value.value.toString()) {
                let jsonRes = {};

                jsonRes.Key = index++;

                try {
                    jsonRes.Record = JSON.parse(res.value.value.toString('utf8'));
                } catch (err) {
                    console.log(err);
                    jsonRes.Record = res.value.value.toString('utf8');
                }

                allResults.push(jsonRes);
            }
            if (res.done) {
                await resultsIterator.close();
                return allResults;
            }
        }
    }

}

module.exports = AITrustAssetContract;