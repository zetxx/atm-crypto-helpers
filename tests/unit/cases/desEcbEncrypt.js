const tap = require('tap');
const lib = require('../../../index');

tap.test('desEcbEncrypt', (t) => {
    t.equal(lib.helpers.desEcbEncrypt('10101010101010101010101010101010', '10101010101010101010101010101010'), 'DD7515F2BFC17F85DD7515F2BFC17F85');
    t.end();
});
