const tap = require('tap');
const lib = require('../../../index');

tap.test('desDerive', (t) => {
    t.equal(lib.helpers.desDerive('10101010101010101010101010101010', '10101010101010101010101010101010').toString('hex'), 'dd7515f2bfc17f85dd7515f2bfc17f8586e8f132ce5e5546dd7515f2bfc17f85');
    t.end();
});
