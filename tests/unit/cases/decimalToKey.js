const tap = require('tap');
const lib = require('../../../index');

tap.test('decimalToKey', (t) => {
    t.equal(lib.decimalToKey('111222333444'), '6FDE4DBC');
    t.end();
});
