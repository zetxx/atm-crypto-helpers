const tap = require('tap');
const lib = require('../../../index');

tap.test('cardMasterKeyDerivation', (t) => {
    // 4.0 (EMV 2000)
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04'}, {emvVersion: '4.0'}), '38CE016813F86BC72634851F25523DF1', 'EMV 2000');

    // 4.1, option A
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04'}, {emvVersion: '4.1', type: 'a'}), '38CE016813F86BC72634851F25523DF1', 'EMV 4.1, option A');

    // 4.1, option B
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04'}, {emvVersion: '4.1', type: 'b'}), '38CE016813F86BC72634851F25523DF1', 'EMV 4.1, option B, PAN 16');
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '101010101010101010', panSeqNum: '04'}, {emvVersion: '4.1', type: 'b'}), '54D59B67372A16D65EDA1C38F2D9543E', 'EMV 4.1, option B, PAN 18');

    // 4.2, option A
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04'}, {emvVersion: '4.2', type: 'a'}), '38CE016813F86BC72634851F25523DF1', 'EMV 4.2, option A');

    // 4.2, option B
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04'}, {emvVersion: '4.2', type: 'b'}), '38CE016813F86BC72634851F25523DF1', 'EMV 4.2, option B, PAN 16');
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '101010101010101010', panSeqNum: '04'}, {emvVersion: '4.2', type: 'b'}), '54D59B67372A16D65EDA1C38F2D9543E', 'EMV 4.2, option B, PAN 18');

    // 4.3, option A
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04'}, {emvVersion: '4.3', type: 'a'}), '38CE016813F86BC72634851F25523DF1', 'EMV 4.3, option A');

    // 4.3, option B
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04'}, {emvVersion: '4.3', type: 'b'}), '38CE016813F86BC72634851F25523DF1', 'EMV 4.3, option B, PAN 16');
    t.equal(lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '101010101010101010', panSeqNum: '04'}, {emvVersion: '4.3', type: 'b'}), '54D59B67372A16D65EDA1C38F2D9543E', 'EMV 4.3, option B, PAN 18');

    t.end();
});
