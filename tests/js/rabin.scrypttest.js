const path = require('path');
const { expect } = require('chai');
const { buildContractClass } = require('scrypttest');
let bsv = require('bsv')
let BN = bsv.crypto.BN
const{ generatePrivKey, privKeyToPubKey, sign } = require('rabinsig');
const {
    getRandomInt,
    getRandomHex
    } = require('../../node_modules/rabinsig/src/utils');

function toLESM(hexNumBE) {
    let n = new BN(hexNumBE, 'hex')
    let m = n.toSM({ endian: 'little'} )
    return m.toString('hex')
}

describe('Test sCrypt contract RabinSignature In Javascript', () => {
    let demo;

    before(() => {
        const RabinSignature = buildContractClass(path.join(__dirname, '../../contracts/rabin.scrypt'));
        rabin = new RabinSignature();
    });

    for(var i = 0; i<200; i++){
    // rabinsig JS library random tests:
    it('rabinsig random should return true', () => {
        let key = generatePrivKey();
        // console.log("P,Q: "+key.p+", "+key.q);
        let nRabin = privKeyToPubKey(key.p, key.q);
        // console.log("nRabin: "+nRabin);
        let dataHex = '0x'+getRandomHex(getRandomInt(33,100));
        // console.log("dataHex: "+dataHex);
        let signatureResult = sign(dataHex, key.p, key.q, nRabin);
        // console.log("sig: "+signatureResult.signature);
        //console.log(signatureResult);
        let paddingByteString='0x'+ new Array(signatureResult.paddingByteCount*2 + 1).join( '0' );
 
        // console.log(paddingByteString);
        //verifySig(int sig, bytes msg, bytes padding, int n)
       
        expect(rabin.verifySig('0x' + toLESM(signatureResult.signature.toString(16)),
            dataHex,
            paddingByteString,
            '0x' + toLESM(nRabin.toString(16)))).to.equal(true);
    });
    }

    it('should return false with wrong padding', () => {
        expect(rabin.verifySig('0xcce42011b595b8ef7742710a4492a130e4b7e020097044e7b86258f82ae25f0467e8a0141ae5afd7038810f692f52d43fbb03363b8320d3b43dc65092eddf112', '0x00112233445566778899aabbccddeeff', '0x00', '0x2152a6f5d120e1f50ba67a637ac4293f2c9f1f47761ad1880d3cb6f908a48733aa24f54c679e3bc1c11868b309590c094f56efa4bec4543c7a81abdd96575215')).to.equal(false);
    });

    it('should return false with wrong signature', () => {
        expect(rabin.verifySig('0xdde42011b595b8ef7742710a4492a130e4b7e020097044e7b86258f82ae25f0467e8a0141ae5afd7038810f692f52d43fbb03363b8320d3b43dc65092eddf112', '0x00112233445566778899aabbccddeeff', '0x00000000', '0x2152a6f5d120e1f50ba67a637ac4293f2c9f1f47761ad1880d3cb6f908a48733aa24f54c679e3bc1c11868b309590c094f56efa4bec4543c7a81abdd96575215')).to.equal(false);
    });
});