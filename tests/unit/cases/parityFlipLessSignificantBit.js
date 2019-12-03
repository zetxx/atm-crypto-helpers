const tap = require('tap');
const lib = require('../../../index');

tap.test('parityFlipLessSignificantBit', (t) => {
    t.equal(lib.helpers.parityFlipLessSignificantBit()(255), 254, 'flipped');
    t.equal(lib.helpers.parityFlipLessSignificantBit()(1), 1, 'not flipped');
    t.end();
});
