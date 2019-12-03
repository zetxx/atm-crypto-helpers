const tap = require('tap');
const lib = require('../../../index');

tap.test('cardCommonSessionKeyDerivation', (t) => {
    // 38CE016813F86BC72634851F25523DF1
    var cardMasterKey = lib.cardMasterKeyDerivation({mkac: '10101010101010101010101010101010', pan: '1010101010101010', panSeqNum: '04'}, {emvVersion: '4.1', type: 'a'});

    // 4.0 (EMV 2000)
    // 4.1
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0001', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '00000000000000000000000000000000'}
    ), 'BE8792CDF3AC9B2B24130A1ACF1761AF', 'EMV version 4.0 && 4.1, small ATC, 0 initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '00000000000000000000000000000000'}
    ), '575B83E7BB14D446ADDFD9F74CB4D762', 'EMV version 4.0 && 4.1, medium ATC, 0 initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0FFF', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '00000000000000000000000000000000'}
    ), 'F04AD3CD653937E67072340942D1F5C7', 'EMV version 4.0 && 4.1, big ATC, 0 initial vector');

    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0001', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '0123456789ABCDEFFEDCBA9876543210'}
    ), '73EE04E0FEB5BC55CBBA1AEF3D0CAD54', 'EMV version 4.0 && 4.1, small ATC, some initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '0123456789ABCDEFFEDCBA9876543210'}
    ), 'B323C2AC3DE14EB5488CCC96B2AFE358', 'EMV version 4.0 && 4.1, medium ATC, some initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0FFF', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '0123456789ABCDEFFEDCBA9876543210'}
    ), 'D8F2F4FCE6C50B37AFE858ECC9953640', 'EMV version 4.0 && 4.1, big ATC, some initial vector');

    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0001', cardMasterKey, emvVersion: '4.1', treeHeight: 2, branchFactor: 16, initialisationVector: '00000000000000000000000000000000'}
    ), '75392CEF8726F5F0D39D1D57D94C528B', 'EMV version 4.0 && 4.1, small ATC, 0 initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 2, branchFactor: 16, initialisationVector: '00000000000000000000000000000000'}
    ), 'B99ADB0267F00612C3F667851FC5A207', 'EMV version 4.0 && 4.1, medium ATC, 0 initial vector');
    // t.throws(lib.cardCommonSessionKeyDerivation(
    //     {atc: '0FFF', cardMasterKey, emvVersion: '4.1', treeHeight: 2, branchFactor: 16, initialisationVector: '00000000000000000000000000000000'}
    // ));

    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0001', cardMasterKey, emvVersion: '4.1', treeHeight: 2, branchFactor: 16, initialisationVector: '0123456789ABCDEFFEDCBA9876543210'}
    ), '382E9091D0ECAEB359F2F84E8F36A04E', 'EMV version 4.0 && 4.1, small ATC, some initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 2, branchFactor: 16, initialisationVector: '0123456789ABCDEFFEDCBA9876543210'}
    ), 'F813BC148E3F0D0636A4951E71DBA279', 'EMV version 4.0 && 4.1, medium ATC, some initial vector');
    // t.equal(lib.cardCommonSessionKeyDerivation(
    //     {atc: '0FFF', cardMasterKey, emvVersion: '4.1', treeHeight: 2, branchFactor: 16, initialisationVector: '0123456789ABCDEFFEDCBA9876543210'}
    // ), '05C73D93CB42385265B58B83177EA19E', 'EMV version 4.0 && 4.1, big ATC, some initial vector');

    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0001', cardMasterKey, emvVersion: '4.1', treeHeight: 16, branchFactor: 2, initialisationVector: '00000000000000000000000000000000'}
    ), 'A3B4BE9CB4A32C72EBAFE5E073C17740', 'EMV version 4.0 && 4.1, small ATC, 0 initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 16, branchFactor: 2, initialisationVector: '00000000000000000000000000000000'}
    ), '3BC01D077913597DD065FCC1936A2971', 'EMV version 4.0 && 4.1, medium ATC, 0 initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0FFF', cardMasterKey, emvVersion: '4.1', treeHeight: 16, branchFactor: 2, initialisationVector: '00000000000000000000000000000000'}
    ), '74436F3BB4CB970136E8199FC662DECC', 'EMV version 4.0 && 4.1, big ATC, 0 initial vector');

    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0001', cardMasterKey, emvVersion: '4.1', treeHeight: 16, branchFactor: 2, initialisationVector: '0123456789ABCDEFFEDCBA9876543210'}
    ), 'D0EF91084CCF81DE9A5812897C8D8963', 'EMV version 4.0 && 4.1, small ATC, some initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 16, branchFactor: 2, initialisationVector: '0123456789ABCDEFFEDCBA9876543210'}
    ), 'F49D1F9509163625BA86FFAC3D451CD7', 'EMV version 4.0 && 4.1, medium ATC, some initial vector');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0FFF', cardMasterKey, emvVersion: '4.1', treeHeight: 16, branchFactor: 2, initialisationVector: '0123456789ABCDEFFEDCBA9876543210'}
    ), 'C03BE700FEB22ECDAAD8BC1F2242B2A6', 'EMV version 4.0 && 4.1, big ATC, some initial vector');

    // 4.2
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0001', cardMasterKey, emvVersion: '4.2'}
    ), '2143014BACF6AB492C02F2403401EF29', 'EMV version 4.2, small ATC');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.2'}
    ), 'D6D6705A61B2F0A3733C6EFF50B61D67', 'EMV version 4.2, medium ATC');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0FFF', cardMasterKey, emvVersion: '4.2'}
    ), '46097BB2BDCF4BE7B6F7554F80A8C874', 'EMV version 4.2, big ATC');

    // TODO
    // 4.3
    // t.equal(lib.cardCommonSessionKeyDerivation(
    //     {atc: '0102', cardMasterKey, emvVersion: '4.3', n: 16}
    // ), '411FA74F8ADB490C0C6A10C8D879A95B', 'EMV version 4.x, xx ATC, xx initial vector');
    // t.equal(lib.cardCommonSessionKeyDerivation(
    //     {atc: '0102', cardMasterKey, emvVersion: '4.3', n: 8}
    // ), 'B2340A8DCB89790F0A763C49ADC28C87', 'EMV version 4.x, xx ATC, xx initial vector');

    // enforced parity
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '00000000000000000000000000000000', parity: 'odd'}
    ), '575B83E6BA15D546ADDFD9F74CB5D662', 'EMV version 4.0 && 4.1, medium ATC, 0 initial vector, odd parity');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '00000000000000000000000000000000', parity: 'even'}
    ), '565A82E7BB14D447ACDED8F64DB4D763', 'EMV version 4.0 && 4.1, medium ATC, 0 initial vector, even parity');

    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '0123456789ABCDEFFEDCBA9876543210', parity: 'odd'}
    ), 'B323C2AD3DE04FB5498CCD97B3AEE358', 'EMV version 4.0 && 4.1, medium ATC, some initial vector, odd parity');
    t.equal(lib.cardCommonSessionKeyDerivation(
        {atc: '0022', cardMasterKey, emvVersion: '4.1', treeHeight: 8, branchFactor: 4, initialisationVector: '0123456789ABCDEFFEDCBA9876543210', parity: 'even'}
    ), 'B222C3AC3CE14EB4488DCC96B2AFE259', 'EMV version 4.0 && 4.1, medium ATC, some initial vector, even parity');

    t.end();
});
