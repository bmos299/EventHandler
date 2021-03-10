'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const morgan = require('morgan');
const fs = require('fs');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('../config/swagger.json');
const network = require('./fabric/network.js');
const { body, query, header ,validationResult } = require('express-validator');
const { Console } = require('console');

const app = express();
app.use(morgan('combined'));
app.use(bodyParser.json({ limit: '50mb' }));
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use(cors());

const validAssetTypes = ['Data', 'Linear_Mode', 'Performance_Claim', 'Model_Inference'];
const validTransformationTypes = ['Aggregation', 'QueryFilter', 'LinearRegressionTraining'];


// Create a new asset
app.post('/AITrustAssets', [
    header('x-org-name').optional().isIn(network.supportedOrgs),
    body('assetType').isString().isIn(validAssetTypes),
    body('propertyHashes').custom(value => { return typeof value === 'object' && value !== null}),
    body('propertyValues').custom(value => { return typeof value === 'object' && value !== null}),
    body('sourceAssets').optional().isArray(),
    body('transformationType').optional().isIn(validTransformationTypes),
    body('transformationInfo').optional().custom(value => { return typeof value === 'object' && value !== null}),
    body('otherInfo').isArray()
    ], async(req, res) => {
    
    console.log("Enter: POST /AITrustAssets");
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() })
    }

    let networkObj = await network.connectToNetwork(req.header(`x-org-name`));
    let assetType = req.body.assetType;
    let propertyHashes = req.body.propertyHashes;
    let propertyValues = req.body.propertyValues;
    let lineageInfo = {
        sourceAssets: req.body.sourceAssets,
        transformationType: req.body.transformationType,
        transformationInfo: req.body.transformationInfo
    };
    let otherInfo = req.body.otherInfo;

    console.log(`assetType: ${assetType}, propertyHashes: ${propertyHashes}, 
        propertyValues: ${propertyValues}, lineageInfo: ${lineageInfo}, otherInfo: ${otherInfo},`);

    //submit request
    let response = await network.createAITrustAsset(networkObj, assetType, 
        JSON.stringify(propertyHashes), JSON.stringify(propertyValues), 
        JSON.stringify(lineageInfo), JSON.stringify(otherInfo));

    let parsedResponse = await JSON.parse(response);
    res.send(parsedResponse);
});


// Get assets
app.get('/AITrustAssets', 
[ 
  header('x-org-name').optional().isIn(network.supportedOrgs),
  query('assetType').isString().isIn(validAssetTypes),
  query('assetOwner').optional().isString()],
async(req, res) => {
    console.log("Enter: GET /AITrustAssets");

    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() })
    }

    console.log(`assetType: ${req.query.assetType}, assetOwner: ${req.query.assetOwner}`);

    let response;
    let networkObj = await network.connectToNetwork(req.header(`x-org-name`));

    if( typeof req.query.assetOwner !== 'undefined'){
        console.log("Calling queryAITrustAssetsByOwner");
        response = await network.queryAITrustAssetsByOwner(networkObj, req.query.assetType, req.query.assetOwner);
    } else {
        console.log("Calling queryAITrustAssetsByType");
        response = await network.queryAITrustAssetsByType(networkObj, req.query.assetType);
    }

    let parsedResponse = await JSON.parse(response);
    res.json(parsedResponse);

});


// Get asset by assetId
app.get('/AITrustAssets/:assetUUID', [ header('x-org-name').optional().isIn(network.supportedOrgs) ] ,async(req, res) => {
    console.log("Enter: GET /AITrustAssets/:assetUUID");
    let networkObj = await network.connectToNetwork(req.header(`x-org-name`));
    let response = await network.readAITrustAsset(networkObj, req.params.assetUUID);
    let parsedResponse = await JSON.parse(response);
    res.json(parsedResponse);

});

// Delete an asset
app.delete('/AITrustAssets/:assetUUID', [header('x-org-name').optional().isIn(network.supportedOrgs)] ,async(req, res) => {
    console.log("Enter: DELETE /AITrustAssets/:assetUUID");
    let networkObj = await network.connectToNetwork(req.header(`x-org-name`));
    let response = await network.deleteAITrustAsset(networkObj, req.params.assetUUID);
    let parsedResponse = await JSON.parse(response);
    res.send(parsedResponse);
});

//update an existing asset (replacing the file)
app.patch('/AITrustAssets/:assetUUID', [
    header('x-org-name').optional().isIn(network.supportedOrgs),
    body('propertyHashes').optional().custom(value => { return typeof value === 'object' && value !== null}),
    body('propertyValues').optional().custom(value => { return typeof value === 'object' && value !== null}),
    body('sourceAssets').optional().isArray(),
    body('transformationType').optional().isIn(validTransformationTypes),
    body('transformationInfo').optional().custom(value => { return typeof value === 'object' && value !== null}),
    body('otherInfo').optional().isArray()
    ], async(req, res) => {
    
    console.log("Enter: PATCH /AITrustAssets:assetUUID");
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }

    if(typeof req.body.propertyHashes === "undefined" && 
        typeof req.body.propertyValues === "undefined" && 
        typeof req.body.sourceAssets === "undefined" &&
        typeof req.body.transformationType === "undefined" &&
        typeof req.body.transformationInfo === "undefined" &&
        typeof req.body.otherInfo === "undefined"){
            //no changes were actually submitted
            return res.status(422).json({ err: "No changes were provided" });
    }

    let networkObj = await network.connectToNetwork(req.header(`x-org-name`));
    let assetUUID = req.params.assetUUID;
    let propertyHashes = typeof req.body.propertyHashes == "undefined" ? null : req.body.propertyHashes;
    let propertyValues = typeof req.body.propertyValues == "undefined" ? null : req.body.propertyValues;
    let otherInfo = typeof req.body.otherInfo == "undefined" ? null : req.body.otherInfo;
    let lineageInfo = null;
    let sourceAssets =  typeof req.body.sourceAssets == "undefined" ? null : req.body.sourceAssets;
    let transformationType = typeof req.body.transformationType == "undefined" ? null : req.body.transformationType;
    let transformationInfo = typeof req.body.transformationInfo == "undefined" ? null : req.body.transformationInfo;

    
    //populate lineage info object if there are modifications to it's attributes
    if (sourceAssets || transformationType || transformationInfo) {
        lineageInfo = {};
        if(sourceAssets)
            lineageInfo.sourceAssets = sourceAssets;
        if(transformationType)
            lineageInfo.transformationType = transformationType;
        if(transformationInfo)
            lineageInfo.transformationInfo = transformationInfo;
    }


    console.log(`assetUUID: ${assetUUID}, propertyHashes: ${propertyHashes}, 
        propertyValues: ${propertyValues}, lineageInfo: ${lineageInfo}, otherInfo: ${otherInfo},`);

    //submit request
    let response = await network.updateAITrustAsset(networkObj, assetUUID, 
        JSON.stringify(propertyHashes), JSON.stringify(propertyValues), JSON.stringify(lineageInfo), JSON.stringify(otherInfo));
  
    let parsedResponse = JSON.parse(response);
    res.send(parsedResponse);
});



app.post('/getHistoryForAITrustAsset', async(req, res) => {
    let response = await network.getHistoryForAITrustAsset(req.body.assetId);
    res.send(response);
});

app.get('/health', async (req, res) => {
    console.log("@ /health");
    res.json({
        name: "AITrust Asset Server",
        status: "UP",
      });    
});

app.get('/', async (req, res) => {
    console.log("@ /");
    res.json({
        name: "AITrust Asset Server",
        status: "UP",
      });    
});

app.listen(process.env.PORT || 8081);

