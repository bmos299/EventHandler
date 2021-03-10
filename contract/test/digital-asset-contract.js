/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { ChaincodeStub, ClientIdentity } = require('fabric-shim');
const { AITrustAssetContract } = require('..');
const winston = require('winston');

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const sinon = require('sinon');
const sinonChai = require('sinon-chai');

chai.should();
chai.use(chaiAsPromised);
chai.use(sinonChai);

class TestContext {

    constructor() {
        this.stub = sinon.createStubInstance(ChaincodeStub);
        this.clientIdentity = sinon.createStubInstance(ClientIdentity);
        this.logging = {
            getLogger: sinon.stub().returns(sinon.createStubInstance(winston.createLogger().constructor)),
            setLevel: sinon.stub(),
        };
    }

}

describe('AITrustAssetContract', () => {

    let contract;
    let ctx;

    beforeEach(() => {
        contract = new AITrustAssetContract();
        ctx = new TestContext();
        ctx.stub.getState.withArgs('1001').resolves(Buffer.from('{"value":"aitrust asset 1001 value"}'));
        ctx.stub.getState.withArgs('1002').resolves(Buffer.from('{"value":"aitrust asset 1002 value"}'));
    });

    describe('#aitrustAssetExists', () => {

        it('should return true for a aitrust asset', async () => {
            await contract.aitrustAssetExists(ctx, '1001').should.eventually.be.true;
        });

        it('should return false for a aitrust asset that does not exist', async () => {
            await contract.aitrustAssetExists(ctx, '1003').should.eventually.be.false;
        });

    });

    describe('#createAITrustAsset', () => {

        it('should create a aitrust asset', async () => {
            await contract.createAITrustAsset(ctx, '1003', 'aitrust asset 1003 value');
            ctx.stub.putState.should.have.been.calledOnceWithExactly('1003', Buffer.from('{"value":"aitrust asset 1003 value"}'));
        });

        it('should throw an error for a aitrust asset that already exists', async () => {
            await contract.createAITrustAsset(ctx, '1001', 'myvalue').should.be.rejectedWith(/The aitrust asset 1001 already exists/);
        });

    });

    describe('#readAITrustAsset', () => {

        it('should return a aitrust asset', async () => {
            await contract.readAITrustAsset(ctx, '1001').should.eventually.deep.equal({ value: 'aitrust asset 1001 value' });
        });

        it('should throw an error for a aitrust asset that does not exist', async () => {
            await contract.readAITrustAsset(ctx, '1003').should.be.rejectedWith(/The aitrust asset 1003 does not exist/);
        });

    });

    describe('#updateAITrustAsset', () => {

        it('should update a aitrust asset', async () => {
            await contract.updateAITrustAsset(ctx, '1001', 'aitrust asset 1001 new value');
            ctx.stub.putState.should.have.been.calledOnceWithExactly('1001', Buffer.from('{"value":"aitrust asset 1001 new value"}'));
        });

        it('should throw an error for a aitrust asset that does not exist', async () => {
            await contract.updateAITrustAsset(ctx, '1003', 'aitrust asset 1003 new value').should.be.rejectedWith(/The aitrust asset 1003 does not exist/);
        });

    });

    describe('#deleteAITrustAsset', () => {

        it('should delete a aitrust asset', async () => {
            await contract.deleteAITrustAsset(ctx, '1001');
            ctx.stub.deleteState.should.have.been.calledOnceWithExactly('1001');
        });

        it('should throw an error for a aitrust asset that does not exist', async () => {
            await contract.deleteAITrustAsset(ctx, '1003').should.be.rejectedWith(/The aitrust asset 1003 does not exist/);
        });

    });

});