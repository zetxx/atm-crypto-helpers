const tap = require('tap');
const lib = require('../../../index');

tap.test('encodePinBlock', (t) => {
    t.equal(lib.helpers.encodePinBlock('041235FEFEFEFEFE'), '041235?>?>?>?>?>');
    t.end();
});
