'use strict';

class AITrustAsset {

    /**
     *
     * AITrustAsset
     *
     * Constructor for a AITrustAsset object.
     *
     * @param {String} assetType - Type of aitrust asset.
     * @param {String} assetUUID - Unique identifier of the aitrust asset.
     * @param {Map} assetHashes - Hashmap with hashes for aitrust asset properties.
     * @param {Map} plainTextContent - Hashmap with attribute values.
     * @param {Object} lineageInfo - aitrust asset lineage info
     * @param {Array} otherInfo - additional information on this asset
     * @param {String} assetOwner - Organization name that owns this asset

     * @returns - AITrustAsset object
     */

    constructor(assetType, assetUUID, assetHashes, plainTextContent, lineageInfo, otherInfo, assetOwner) {
        this.assetType = assetType;
        this.assetUUID = assetUUID;
        this.assetHashes = assetHashes;
        this.plainTextContent = plainTextContent;
        this.lineageInfo = lineageInfo;
        this.otherInfo = otherInfo;
        this.assetOwner = assetOwner;
        return this;
    }
}

module.exports = AITrustAsset;