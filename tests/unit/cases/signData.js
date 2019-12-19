const tap = require('tap');
const lib = require('../../../index');

tap.test('signData emv version 4.1', (t) => {
    var cardKeys = lib.deriveRuntimeCardKeys({
        masterKey: {mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04', mkEmvVersion: '4.1', type: 'a'},
        sessionKey: {atc: '0001', skEmvVersion: '4.1', treeHeight: 8, branchFactor: 4, parity: 'odd'}
    });
    t.equal(lib.signData('f01f01f01f01f01f01f01f01', 'hex', undefined, undefined, {
        paddingMethod: '1',
        masterKey: cardKeys.masterKey,
        sessionKey: cardKeys.sessionKey
    }), 'C21687D53F9F048E', 'some TX data, padding method 1 - 00...00');
    t.equal(lib.signData('f01f01f01f01f01f01f01f01', 'hex', undefined, undefined, {
        paddingMethod: '2',
        masterKey: cardKeys.masterKey,
        sessionKey: cardKeys.sessionKey
    }), 'B7BBE6B2CA55AA40', 'some TX data, padding method 2 - 80...00');

    t.equal(lib.signData('0000000010000000000000000710000000000007101302050030901B6A3C00005503A4A082', 'hex', undefined, undefined, {
        paddingMethod: '1',
        masterKey: cardKeys.masterKey,
        sessionKey: cardKeys.sessionKey
    }), '810682021324857A', 'real TX data, padding method 1 - 00...00');
    t.equal(lib.signData('0000000010000000000000000710000000000007101302050030901B6A3C00005503A4A082', 'hex', undefined, undefined, {
        paddingMethod: '2',
        masterKey: cardKeys.masterKey,
        sessionKey: cardKeys.sessionKey
    }), '46BBE23E77EF5DAA', 'real TX data, padding method 2 - 80...00');

    t.end();
});

tap.test('signData emv version vsdc', (t) => {
    var cardKeys = lib.deriveRuntimeCardKeys({
        masterKey: {mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04', mkEmvVersion: '4.1', type: 'a'}
    });
    t.equal(lib.signData('0000000010000000000000000710000000000007101302050030901B6A3C00005503A4A082', 'hex', undefined, undefined, {
        paddingMethod: '1',
        signEmvVersion: 'vsdc',
        masterKey: cardKeys.masterKey
    }), 'E96582062870966B', 'some TX data, padding method 1 - 00...00');
    t.end();
});
