const tap = require('tap');
const lib = require('../../../index');

tap.test('getPin', (t) => {
    t.equal(lib.getPin('1234', '1010101010101010', '10101010101010101010101010101010'), '7=>80>>79=9<>583');
    t.end();
});
