const cardCrypto = require('node-cardCrypto');
const crypto = require('crypto');

const des3EcbEncrypt = (key, data) => cardCrypto.des.ecb_encrypt(key, data);
const des3CbcEncrypt = (key, data) => cardCrypto.des.cbc_encrypt(key, data);
const des3CbcDecrypt = (key, data) => cardCrypto.des.cbc_decrypt(key, data);
const aesEcbEncrypt = (key, data) => cardCrypto.aes.ecb_encrypt(key, data);

var fitParseRule = [
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
    var chunk = data.slice(0, 3);
    data = data.slice(3);
    if (chunk.length === 0) {
        return result.join('');
    }
    chunk = ('0' + parseInt(chunk).toString(16).toUpperCase()).slice(-2);
    result.push(chunk);
    return decimalToKey(data, result);
};

const xor = (items) => {
    var a = Buffer.from(items.shift(), 'hex');
    var b = Buffer.from(items.shift(), 'hex');
    var c = Buffer.from(a.map((el, idx) => el ^ b[idx])).toString('hex').toUpperCase();
    if (items.length > 0) {
        items.unshift(c);
        return xor(items);
    }
    return c;
};

const getPinBlock = (pin, card) => {
    // A 16-digit block is made from the:
    let block1 = [
        0, // digit 0
        pin.length, // the length of the PIN
        pin // the PIN
    ].concat((new Array(16)).fill('F')) // pad character (hexadecimal F)
        .join('')
        .slice(0, 16);

    // Another 16-digit block is made from four zeros and the 12 right-most digits of the account number
    let block2 = [
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
    des3EcbEncrypt(key, getPinBlock(pin, card))
);

const padString = (str, {size = 0, direction = 'left', symbol = '0'} = {}) => {
    var padString = symbol.repeat(size);

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
        } else {
            return byte;
        }
    };
};

const des3Derive = (mkac, derived) => Buffer.from([des3EcbEncrypt(mkac, derived), des3EcbEncrypt(mkac, xor([derived, 'F'.repeat(16)]))].join(''), 'hex');

const cardMasterKeyDerivation = ({mkac, pan, panSeqNum = '00'}, {emvVersion, type = 'a'} = {}) => {
    var derived = [];
    var panAndSeqNum = `${pan}${panSeqNum}`;

    switch (emvVersion) {
        case '4.0':
            derived = Buffer.from(des3Derive(mkac, padString(panAndSeqNum, {size: 16})), 'hex')
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

                        derived = des3Derive(mkac, derived)
                            .map(parityFlipLessSignificantBit());
                    }
                    break;
                default:
                    throw new Error('cardMasterKeyDerivation.unknownType');
            }
            break;
        default:
            throw new Error('cardMasterKeyDerivation.unknownEmvVersion');
    }
    return derived
        .toString('hex')
        .toUpperCase();
};

const cardCommonSessionKeyDerivation = ({emvVersion, algorithmBlockSize, treeHeight, branchFactor, initialisationVector = '00000000000000000000000000000000', atc, cardMasterKey, parity = 'none'}) => {
    // algorithm block size: in BYTES (AES - 128 bits = 16 bytes, DES - 64 bits = 8 bytes)
    // tree height, i.e. the number of levels of intermediate keys in the tree excluding the base level;
    // branch factor, i.e. the number of “child” keys that a “parent” key (which must be one level lower in the tree) derives

    var cardMasterKeyLength = cardMasterKey.length;
    var keySize = cardMasterKeyLength * 4; // key size in BITS
    var derived;

    switch (emvVersion) {
        case '4.0': // EMV 2000
        case '4.1': // same algorithm as EMV2000
            var atcDec = parseInt(atc, 16);
            if (atcDec > Math.pow(branchFactor, treeHeight)) {
                throw new Error('cardCommonSessionKeyDerivation.atcAboveMaxValue');
            }
            var ivLength = initialisationVector.length; // SHOULD BE 32 symbols (16 bytes) !!!
            var derivedKeys = [[cardMasterKey]];
            var derivedKeysRow = [];
            var i, j; // counters
            var jmodb;
            var ivl; // initial vector left half
            var ivr; // initial vector right half
            var leftValue, rightValue;
            var b2 = branchFactor * branchFactor;

            var maxj;
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
                        des3EcbEncrypt(derivedKeys[i - 1][Math.floor(j / branchFactor)], leftValue),
                        des3EcbEncrypt(derivedKeys[i - 1][Math.floor(j / branchFactor)], rightValue)
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
        case '4.2':
            derived = Buffer.from([
                des3EcbEncrypt(cardMasterKey, padString(atc + 'F0', {size: 16, direction: 'right', symbol: '0'})),
                des3EcbEncrypt(cardMasterKey, padString(atc + '0F', {size: 16, direction: 'right', symbol: '0'}))
            ]
                .join('')
                .toUpperCase(), 'hex')
                .map(parityFlipLessSignificantBit(parity));
            break;
        case '4.3':
            if (keySize === (8 * algorithmBlockSize)) {
                derived = aesEcbEncrypt(cardMasterKey, padString(atc, {size: 32, direction: 'right', symbol: '0'})).toUpperCase();
            } else if ((keySize > (8 * algorithmBlockSize)) && (keySize <= (16 * algorithmBlockSize)) && (algorithmBlockSize === 16 || algorithmBlockSize === 8)) {
                derived = Buffer.from([
                    padString(atc + 'F0', {size: algorithmBlockSize * 2, direction: 'right', symbol: '0'}),
                    padString(atc + '0F', {size: algorithmBlockSize * 2, direction: 'right', symbol: '0'})
                ]
                    .map((e) => ((algorithmBlockSize === 16 && aesEcbEncrypt(cardMasterKey, e)) || des3EcbEncrypt(cardMasterKey, e)))
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
    var tmpStr = str.slice(0, 16);
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
const signData = (data, dataFormat = 'hex', {signEmvVersion, paddingMethod = '2', masterKey, sessionKey, key}) => {
    checkHex(data, {minSize: 16});
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
    var dataBlocks = ['0'.repeat(16)].concat(breakString(data));
    var dataBlocksEncrypted = dataBlocks.reduce((a, c, idx) => ((idx && a.push(des3CbcEncrypt(keyUsed[0], xor([c, a[idx - 1]]))) && a) || a), ['0'.repeat(16)]);
    return des3CbcEncrypt(keyUsed[0], des3CbcDecrypt(keyUsed[1], dataBlocksEncrypted.pop()));
};

const deriveRuntimeCardKeys = ({masterKey: {mkac, pan, panSeqNum, mkEmvVersion, type} = {}, sessionKey: {atc, skEmvVersion, treeHeight, branchFactor, parity} = {}}) => {
    var masterKey = cardMasterKeyDerivation({mkac, pan, panSeqNum}, {emvVersion: mkEmvVersion, type});
    var sessionKey = skEmvVersion && cardCommonSessionKeyDerivation({atc, cardMasterKey: masterKey, emvVersion: skEmvVersion, treeHeight, branchFactor, parity});
    return {masterKey, sessionKey};
};

const cryptogramVersionCalcTagValueRules = {
    vsdccv10: {
        '9f10': (data, from = 3, to = 8) => data.slice(from * 2, to * 2)
    }
};

const cryptogramVersionCalcTagValue = (cryptogramVersion, tag, oldValue) => {
    var value = oldValue;
    if (cryptogramVersionCalcTagValueRules && cryptogramVersionCalcTagValueRules[cryptogramVersion] && cryptogramVersionCalcTagValueRules[cryptogramVersion][tag]) { // cryptogramVersion: vsdccv10
        value = cryptogramVersionCalcTagValueRules[cryptogramVersion][tag](oldValue);
    }
    return {[tag]: value};
};

const messageCoordinationNumberGen = (type) => {
    var messageCoordinationNumber = 49;
    return () => {
        if (messageCoordinationNumber > 63) {
            messageCoordinationNumber = 49;
        }
        return String.fromCharCode(messageCoordinationNumber++);
    };
};

const throwOrReturn = ({result, error} = {}) => {
    if (error) {
        throw error;
    }
    return result;
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
    throwOrReturn,
    getTimeVariant,
    messageCoordinationNumberGen,
    cardMasterKeyDerivation,
    cardCommonSessionKeyDerivation,
    signData,
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
        des3Derive,
        parityFlipLessSignificantBit,
        padString,
        getPinBlock,
        encodePinBlock,
        des3EcbEncrypt
    }
};
