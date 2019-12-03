const tap = require('tap');
const lib = require('../../../index');

tap.test('getPinBlock', (t) => {
    t.equal(lib.helpers.getPinBlock('1234', '1010101010101010'), '041235FEFEFEFEFE');
    t.end();
});
