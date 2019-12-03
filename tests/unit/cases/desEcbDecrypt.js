const tap = require('tap');
const lib = require('../../../index');

tap.test('desEcbDecrypt', (t) => {
    t.equal(lib.helpers.desEcbDecrypt('10101010101010101010101010101010', 'DD7515F2BFC17F85DD7515F2BFC17F85'), '10101010101010101010101010101010');
    t.end();
});
