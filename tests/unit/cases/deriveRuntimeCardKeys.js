const tap = require('tap');
const lib = require('../../../index');

tap.test('deriveRuntimeCardKeys derive both keys (master and session)', (t) => {
    var cardKeys = lib.deriveRuntimeCardKeys({
        masterKey: {mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04', mkEmvVersion: '4.1', type: 'a'},
        sessionKey: {atc: '0001', skEmvVersion: '4.1', treeHeight: 8, branchFactor: 4, parity: 'odd'}
    });
    t.equal(cardKeys.masterKey, '38CE016813F86BC72634851F25523DF1', 'derive master');
    t.equal(cardKeys.sessionKey, 'BF8692CDF2AD9B2A25130B1ACE1661AE', 'derive session');
    t.end();
});

tap.test('deriveRuntimeCardKeys derive master only', (t) => {
    var cardKeys = lib.deriveRuntimeCardKeys({
        masterKey: {mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04', mkEmvVersion: '4.1', type: 'a'}
    });
    t.equal(cardKeys.masterKey, '38CE016813F86BC72634851F25523DF1', 'derive master');
    t.equal(cardKeys.sessionKey, undefined, 'derive session is undefined');
    t.end();
});
