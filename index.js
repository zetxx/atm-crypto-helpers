const {aesEcbEncrypt, desEcbEncrypt, desCbcEncrypt, desCbcDecrypt, desEcbDecrypt, keyblockDecrypt} = require('./lib/crypt');
const crypto = require('crypto');

const fitParseRule = [
    {name: 'piddx', len: 2},
    {name: 'pfiid', len: 10},
    {name: 'pstdx', len: 2},
    {name: 'pagdx', len: 2},
    {name: 'pmxpn', len: 2},
    {name: 'pckln', len: 2},
    {name: 'pinpd', len: 2},
    {name: 'pandx', len: 2},
    {name: 'panln', len: 2},
    {name: 'panpd', len: 2},
    {name: 'prcnt', len: 2},
    {name: 'pofdx', len: 2},
    {name: 'pdctb', len: 16},
    {name: 'pekey', len: 16},
    {name: 'pindx', len: 6},
    {name: 'plndx', len: 2},
    {name: 'pmmsr', len: 2},
    {name: 'reserved.1', len: 6},
    {name: 'pbfmt', len: 2}
];

const decimalToKey = (data, result = []) => {
    let chunk = data.slice(0, 3);
    data = data.slice(3);
    if (chunk.length === 0) {
        return result.join('');
    }
    chunk = ('0' + parseInt(chunk).toString(16).toUpperCase()).slice(-2);
    result.push(chunk);
    return decimalToKey(data, result);
};

const xor = (items) => {
    const a = Buffer.from(items.shift(), 'hex');
    const b = Buffer.from(items.shift(), 'hex');
    const c = Buffer.from(a.map((el, idx) => el ^ b[idx])).toString('hex').toUpperCase();
    if (items.length > 0) {
        items.unshift(c);
        return xor(items);
    }
    return c;
};

const getPinBlock = (pin, card) => {
    // A 16-digit block is made from the:
    const block1 = [
        0, // digit 0
        pin.length, // the length of the PIN
        pin // the PIN
    ].concat((new Array(16)).fill('F')) // pad character (hexadecimal F)
        .join('')
        .slice(0, 16);

    // Another 16-digit block is made from four zeros and the 12 right-most digits of the account number
    const block2 = [
        '0000',
        card.slice(-13).slice(0, 12)
    ].join('');
    return xor([block1, block2]);
};

const encodeDecodePinBlock = [
    ['A', ':'],
    ['B', ';'],
    ['C', '<'],
    ['D', '='],
    ['E', '>'],
    ['F', '?']
].reduce((a, [x, y]) => {
    a.encode[x] = y;
    a.decode[y] = x;
    return a;
}, {encode: {}, decode: {}});

const encodePinBlock = (pinBlock) => pinBlock
    .split('')
    .map((ch) => (encodeDecodePinBlock.encode[ch] || ch))
    .join('');

const getPin = (pin, card, key) => encodePinBlock(
    desEcbEncrypt(key, getPinBlock(pin, card))
);

const padString = (str, {size = 0, direction = 'left', symbol = '0'} = {}) => {
    const padString = symbol.repeat(size);

    if (direction === 'left') {
        return `${padString}${str}`.slice(size * -1);
    } else {
        return `${str}${padString}`.slice(0, size);
    }
};

const parityFlipLessSignificantBit = (parity = 'odd') => {
    return (byte) => {
        if (parity === 'odd') {
            return (((((byte >> 7) & 1) + ((byte >> 6) & 1) + ((byte >> 5) & 1) + ((byte >> 4) & 1) + ((byte >> 3) & 1) + ((byte >> 2) & 1) + ((byte >> 1) & 1) + (byte & 1)) % 2 === 0) && byte ^ 1) || byte;
        } else if (parity === 'even') {
            return (((((byte >> 7) & 1) + ((byte >> 6) & 1) + ((byte >> 5) & 1) + ((byte >> 4) & 1) + ((byte >> 3) & 1) + ((byte >> 2) & 1) + ((byte >> 1) & 1) + (byte & 1)) % 2 === 1) && byte ^ 1) || byte;
        } else if (parity === 'all') {
            return ~byte;
        } else {
            return byte;
        }
    };
};

const desDerive = (mkac, derived) => Buffer.from([desEcbEncrypt(mkac, derived), desEcbEncrypt(mkac, xor([derived, 'F'.repeat(16)]))].join(''), 'hex');

const cardMasterKeyDerivation = ({mkac, pan, panSeqNum = '00'}, {emvVersion, type = 'a'} = {}) => {
    let derived = [];
    let panAndSeqNum = `${pan}${panSeqNum}`;

    switch (emvVersion) {
        case '4.0':
            derived = Buffer.from(desDerive(mkac, padString(panAndSeqNum, {size: 16})), 'hex')
                .map(parityFlipLessSignificantBit());
            break;
        case '4.1':
        case '4.2':
        case '4.3':
            switch (type) {
                case 'a':
                    derived = Buffer.from(cardMasterKeyDerivation({mkac, pan, panSeqNum}, {emvVersion: '4.0'}), 'hex');
                    break;
                case 'b':
                    if (pan.length <= 16) {
                        derived = Buffer.from(cardMasterKeyDerivation({mkac, pan, panSeqNum}, {emvVersion: '4.0'}), 'hex');
                    } else {
                        let panAndSeqNumLen = panAndSeqNum.length;
                        derived = crypto
                            .createHash('sha1')
                            .update(Buffer.from(padString(panAndSeqNum, {size: ((panAndSeqNumLen % 2 === 0 && panAndSeqNumLen) || panAndSeqNumLen + 1), symbol: '0'}), 'hex'))
                            .digest('hex') // create hash
                            .split('')
                            .reduce((a, char) => ((isNaN(parseInt(char)) && a[1].push((char.charCodeAt(0) - 97).toString())) || a[0].push(char)) && a, [[], []]) // put digit values in array 0 and char digit values in array 1
                            .map((a) => a.join('')) // join array 0 and array 1
                            .join('') // join entire array
                            .slice(0, 16); // get first 16 chars(numbers);

                        derived = desDerive(mkac, derived)
                            .map(parityFlipLessSignificantBit());
                    }
                    break;
                default:
                    throw new Error('cardMasterKeyDerivation.unknownType');
            }
            break;
        // case 'v1.6':
        //     let keyUsed = breakString(mkac, {size: mkac.length / 2});
        //     let data1 = Buffer.from(padString(panAndSeqNum, {size: 16, direction: 'left', symbol: '0'}), 'hex');
        //     let data2 = Buffer.from(padString(panAndSeqNum, {size: 16, direction: 'left', symbol: '0'}), 'hex')
        //         .map(parityFlipLessSignificantBit('all'));
        //     derived = [
        //         desEcbEncrypt(keyUsed[0], desEcbDecrypt(keyUsed[1], desEcbEncrypt(keyUsed[0], data1))),
        //         desEcbEncrypt(keyUsed[0], desEcbDecrypt(keyUsed[1], desEcbEncrypt(keyUsed[0], data2)))
        //     ]
        //         .join('');
        //     break;
        default:
            throw new Error('cardMasterKeyDerivation.unknownEmvVersion');
    }
    return derived
        .toString('hex')
        .toUpperCase();
};

const cardCommonSessionKeyDerivation = ({emvVersion, algorithmBlockSize = 8, treeHeight, branchFactor, initialisationVector = '00000000000000000000000000000000', atc, cardMasterKey, parity = 'none'}) => {
    // algorithm block size: in BYTES (AES - 128 bits = 16 bytes, DES - 64 bits = 8 bytes)
    // tree height, i.e. the number of levels of intermediate keys in the tree excluding the base level;
    // branch factor, i.e. the number of “child” keys that a “parent” key (which must be one level lower in the tree) derives

    let cardMasterKeyLength = cardMasterKey.length;
    let keySize = cardMasterKeyLength * 4; // key size in BITS
    let derived;

    switch (emvVersion) {
        case '4.0': // EMV 2000 session key derivation
        case '4.1': // same algorithm as EMV2000
            let atcDec = parseInt(atc, 16);
            if (atcDec > Math.pow(branchFactor, treeHeight)) {
                throw new Error('cardCommonSessionKeyDerivation.atcAboveMaxValue');
            }
            let ivLength = initialisationVector.length; // SHOULD BE 32 symbols (16 bytes) !!!
            let derivedKeys = [[cardMasterKey]];
            let derivedKeysRow = [];
            let i, j; // counters
            let jmodb;
            let ivl; // initial vector left half
            let ivr; // initial vector right half
            let leftValue, rightValue;
            let b2 = branchFactor * branchFactor;

            let maxj;
            for (i = 1; i <= treeHeight; i++) {
                maxj = Math.pow(branchFactor, i) - 1;
                if (atcDec < maxj) {
                    maxj = atcDec;
                }
                for (j = 0; j <= maxj; j++) {
                    jmodb = j % branchFactor;
                    let iTmp = i - 2;
                    ivl = ((derivedKeys[iTmp] && derivedKeys[iTmp][Math.floor(j / b2)]) || initialisationVector).slice(0, ivLength / 2);
                    ivr = ((derivedKeys[iTmp] && derivedKeys[iTmp][Math.floor(j / b2)]) || initialisationVector).slice(ivLength / 2, ivLength);
                    leftValue = xor([
                        ivl,
                        padString(jmodb, {size: 16, direction: 'left', symbol: '0'})
                    ]);
                    rightValue = xor([
                        ivr,
                        padString(jmodb, {size: 16, direction: 'left', symbol: '0'}),
                        padString('F0', {size: 16, direction: 'left', symbol: '0'})
                    ]);
                    derivedKeysRow[j] = [
                        desEcbEncrypt(derivedKeys[i - 1][Math.floor(j / branchFactor)], leftValue),
                        desEcbEncrypt(derivedKeys[i - 1][Math.floor(j / branchFactor)], rightValue)
                    ].join('').toUpperCase();
                }
                derivedKeys.push(derivedKeysRow);
                derivedKeysRow = [];
            }

            derived = Buffer.from(xor([
                derivedKeys[treeHeight][atcDec],
                derivedKeys[treeHeight - 2][Math.floor(atcDec / b2)]
            ]), 'hex')
                .map(parityFlipLessSignificantBit(parity));
            break;
        case '4.2': // common session key derivation
        // case 'v1.6':
            derived = Buffer.from([
                desEcbEncrypt(cardMasterKey, padString(atc + 'F0', {size: 16, direction: 'right', symbol: '0'})),
                desEcbEncrypt(cardMasterKey, padString(atc + '0F', {size: 16, direction: 'right', symbol: '0'}))
            ]
                .join('')
                .toUpperCase(), 'hex')
                .map(parityFlipLessSignificantBit(parity));
            break;
        case '4.3': // common session key derivation
            if (keySize === (8 * algorithmBlockSize)) {
                derived = aesEcbEncrypt(cardMasterKey, padString(atc, {size: 32, direction: 'right', symbol: '0'})).toUpperCase();
            } else if ((keySize > (8 * algorithmBlockSize)) && (keySize <= (16 * algorithmBlockSize)) && (algorithmBlockSize === 16 || algorithmBlockSize === 8)) {
                derived = Buffer.from([
                    padString(atc + 'F0', {size: algorithmBlockSize * 2, direction: 'right', symbol: '0'}),
                    padString(atc + '0F', {size: algorithmBlockSize * 2, direction: 'right', symbol: '0'})
                ]
                    .map((e) => ((algorithmBlockSize === 16 && aesEcbEncrypt(cardMasterKey, e)) || desEcbEncrypt(cardMasterKey, e)))
                    .join('')
                    .slice(0, cardMasterKeyLength)
                    .toUpperCase(), 'hex');
            } else {
                throw new Error('cardCommonSessionKeyDerivation.wrongBlockOrKeySize');
            }
            break;
    }
    return derived
        .toString('hex')
        .toUpperCase();
};

const checkHex = (hex, {minSize = 2, maxSize = Number.MAX_SAFE_INTEGER, size = 0, integrity = 0} = {}) => {
    if (integrity && hex.length % 2 !== 0) {
        throw new Error('hexShouldBeEven');
    } else if (size) {
        if (hex.length !== size) {
            throw new Error('hexSizeDontMatch');
        }
    } else if (hex.length < minSize) {
        throw new Error('hexMinSize');
    } else if (hex.length > maxSize) {
        throw new Error('hexMaxSize');
    } else if (integrity && Buffer.from(hex, 'hex').toString('hex').toUpperCase() !== hex.toUpperCase()) {
        throw new Error('incorrectHexString');
    }
};

const breakString = (str, {size = 2} = {}, out = []) => {
    let tmpStr = str.slice(0, 16);
    str = str.slice(16);
    out.push(tmpStr);
    if (str.length) {
        return breakString(str, {size}, out);
    }
    return out;
};

// padding method '1' - Padding Method 1 in ISO/IEC 9797-1
// All the bytes that are required to be padded are padded with zero
// padding method '2' - identical to ISO/IEC 9797-1 Padding Method 2
// the first byte is a mandatory byte valued '80' (Hexadecimal) followed, if needed, by 0 to N-1 bytes set to '00'
const signData = (data, dataFormat = 'hex', macAlgorithm = '3', macLength = 8, {signEmvVersion, paddingMethod = '2', masterKey, sessionKey, key}) => {
    if (macLength < 4 || macLength > 8) {
        throw new Error('invalidMacLength');
    }
    dataFormat === 'hex' && checkHex(data, {minSize: 16});
    let key2;
    if (key) {
        key2 = key;
        paddingMethod = '1';
    } else if (signEmvVersion === 'vsdc') {
        key2 = masterKey;
    } else {
        key2 = sessionKey;
    }

    data = Buffer.from(data, dataFormat).toString('hex').toUpperCase();

    if (paddingMethod === '2') {
        data = `${data}80`;
    }
    let dataLen = data.length;
    data = padString(data, {size: Math.ceil(dataLen / 16) * 16, direction: 'right', symbol: '0'});
    let keyUsed = breakString(key2, {size: key2.length / 2});
    // TODO: check this !!!
    // var dataBlocks = ['0'.repeat(16)].concat(breakString(data));
    let dataBlocks = breakString(data);
    let dataBlocksEncrypted = dataBlocks.reduce((a, c, idx) => ((idx && a.push(desCbcEncrypt(keyUsed[0], xor([c, a[idx - 1]]))) && a) || (a.push(desCbcEncrypt(keyUsed[0], c)) && a)), []);
    switch (macAlgorithm) {
        case '1':
            return dataBlocksEncrypted.pop().slice(0, macLength * 2);
        // case '2':
        //     return;
        case '3':
            return desCbcEncrypt(keyUsed[0], desCbcDecrypt(keyUsed[1], dataBlocksEncrypted.pop())).slice(0, macLength * 2);
        default:
            throw new Error('badMacAlgorithm');
    }
};

const checkDataSignature = (data, {checkEmvMethod, sessionKey}) => {
    checkHex(data, {minSize: 16});
    let clearData;

    switch (checkEmvMethod) {
        case '1':
            if (!data.arqc || !data.arc) {
                throw new Error('invalidArpcVerificationData');
            }
            clearData = xor([data.arqc, padString(data.arc, {size: 16, direction: 'right', symbol: '0'})]);
            return desEcbEncrypt(sessionKey, clearData);
        case '2':
            if (!data.arqc || !data.csu) {
                throw new Error('invalidArpcVerificationData');
            }
            clearData = data.arqc + data.csu + (data.pad || '');
            // MAC algorithm: '3'
            // MAC length: 4
            return signData(clearData, 'hex', '3', 4, {paddingMethod: '2', sessionKey});
        default:
            throw new Error('invalidArpcMethod');
    }
};

const deriveRuntimeCardKeys = ({masterKey: {mkac, pan, panSeqNum, mkEmvVersion, type} = {}, sessionKey: {atc, skEmvVersion, treeHeight, branchFactor, parity} = {}}) => {
    let masterKey = cardMasterKeyDerivation({mkac, pan, panSeqNum}, {emvVersion: mkEmvVersion, type});
    let sessionKey = skEmvVersion && cardCommonSessionKeyDerivation({atc, cardMasterKey: masterKey, emvVersion: skEmvVersion, treeHeight, branchFactor, parity});
    return {masterKey, sessionKey};
};

const cryptogramVersionCalcTagValueRules = {
    vsdccv10: {
        '9f10': (data, from = 3, to = 8) => data.slice(from * 2, to * 2)
    }
};

const cryptogramVersionCalcTagValue = (cryptogramVersion, tag, oldValue) => {
    let value = oldValue;
    if (cryptogramVersionCalcTagValueRules && cryptogramVersionCalcTagValueRules[cryptogramVersion] && cryptogramVersionCalcTagValueRules[cryptogramVersion][tag]) { // cryptogramVersion: vsdccv10
        value = cryptogramVersionCalcTagValueRules[cryptogramVersion][tag](oldValue);
    }
    return {[tag]: value};
};

const messageCoordinationNumberGen = (type) => {
    let messageCoordinationNumber = 49;
    return () => {
        if (messageCoordinationNumber > 63) {
            messageCoordinationNumber = 49;
        }
        return String.fromCharCode(messageCoordinationNumber++);
    };
};

const getTimeVariant = () => {
    const int64 = Date.now() + Math.floor(Math.random() * 1000);
    const b = Buffer.from((new Array(8)).fill(0));
    const MaxUint32 = 0xFFFFFFFF;

    const big = ~~(int64 / MaxUint32);
    const low = (int64 % MaxUint32) - big;
    b.writeUInt32BE(big, 0);
    b.writeUInt32BE(low, 4);
    return b.slice(-4).toString('hex');
};

const parseFitTable = (fit, list, collection = {}) => {
    let {name, len} = list.shift() || {};
    let chunk = fit.slice(0, len);
    if (chunk && list.length) {
        collection[name] = chunk;
        return parseFitTable(fit.slice(len), list, collection);
    } else {
        return collection;
    }
};

module.exports = {
    decimalToKey,
    getPin,
    getTimeVariant,
    messageCoordinationNumberGen,
    cardMasterKeyDerivation,
    cardCommonSessionKeyDerivation,
    signData,
    checkDataSignature,
    cryptogramVersionCalcTagValue,
    deriveRuntimeCardKeys,
    parseFitTable: (fit) => {
        let newFit = Array.from({length: fit.length / 3}).fill(fit).map((v, idx) => {
            let start = 3 * idx;
            let s = Number(parseInt(v.slice(start, start + 3))).toString(16);
            return `0${s}`.slice(-2);
        }).join('');
        return parseFitTable(newFit, fitParseRule.concat([]));
    },
    helpers: {
        xor,
        desDerive,
        parityFlipLessSignificantBit,
        padString,
        getPinBlock,
        encodePinBlock,
        desEcbEncrypt,
        desEcbDecrypt,
        keyblockDecrypt
    }
};
