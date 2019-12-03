const tap = require('tap');
const lib = require('../../../index');

tap.test('xor', (t) => {
    lib.helpers.xor(['00', '01', '02', '03', '04']);
    t.equal(lib.helpers.xor(['00', '01', '02', '03', '04']), '04');
    t.end();
});
