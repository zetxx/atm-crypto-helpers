const tap = require('tap');
const lib = require('../../../index');

tap.test('cryptogramVersionCalcTagValue vsdccv10', (t) => {
    t.same(lib.cryptogramVersionCalcTagValue('vsdccv10', '9f10', '06010A03A02000FAF1F3'), {'9f10': '03A02000FA'});
    t.end();
});
