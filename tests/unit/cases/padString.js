const tap = require('tap');
const lib = require('../../../index');

tap.test('padString', (t) => {
    t.equal(lib.helpers.padString('1122', {size: 10, direction: 'left', symbol: 'RR'}), 'RRRRRR1122', 'pad string left with R and size 10');
    t.equal(lib.helpers.padString('1122', {size: 10, direction: 'right', symbol: 'RR'}), '1122RRRRRR', 'pad string right with R and size 10');
    t.end();
});
