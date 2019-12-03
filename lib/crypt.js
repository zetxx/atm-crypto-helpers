const crypto = require('crypto');

const keyLenCipherMap = {
    aes: {
        ecb: {
            16: 'aes-128-ecb', // 128 bit key aes ecb mode
            24: 'aes-192-ecb', // 192 bit key aes ecb mode
            32: 'aes-256-ecb' // 256 bit key aes ecb mode
        }
    },
    des: {
        ecb: {
            8: 'des-ecb', // one key des ecb
            16: 'des-ede', //  Two key triple des ecb
            24: 'des-ede3' // Three key triple des ecb
        },
        cbc: {
            8: 'des-cbc', // one key des cbc
            16: 'des-ede-cbc', // Two key triple des cbc
            24: 'des-ede3-cbc' // Three key triple des cbc
        }
    }
};

const getCipherType = ([l1, l2, l3]) => {
    if (keyLenCipherMap[l1] && keyLenCipherMap[l1][l2]) {
        if (!keyLenCipherMap[l1][l2][l3]) {
            throw Error(`key length is invalid. must set to be ${Object.keys(keyLenCipherMap[l1][l2]).join(', ')}`);
        }
        return keyLenCipherMap[l1][l2][l3];
    } else {
        throw Error('Keymap path invalid');
    }
};

const msgBuffAssert = (msg, desired) => {
    if ((msg.length % desired) !== 0) {
        throw Error(`Invalid message length, must set to be multiple ${desired}`);
    }
};

const cipher = (msg, cipherType, key, iv) => {
    var op = crypto.createCipheriv(cipherType, key, iv);
    op.setAutoPadding(false);
    return op.update(msg).toString('hex').toUpperCase();
};

const decipher = (msg, cipherType, key, iv) => {
    var op = crypto.createDecipheriv(cipherType, key, iv);
    op.setAutoPadding(false);
    return op.update(msg).toString('hex').toUpperCase();
};

module.exports = {
    aesEcbEncrypt: (key, msg) => {
        var msgBuf = Buffer.from(msg, 'hex');
        var keyBuf = Buffer.from(key, 'hex');

        msgBuffAssert(msgBuf, 16);
        let cipherType = getCipherType(['aes', 'ecb', keyBuf.length]);

        return cipher(msgBuf, cipherType, keyBuf, '');
    },
    desEcbEncrypt: (key, msg) => {
        var msgBuf = Buffer.from(msg, 'hex');
        var keyBuf = Buffer.from(key, 'hex');

        msgBuffAssert(msgBuf, 8);
        let cipherType = getCipherType(['des', 'ecb', keyBuf.length]);

        return cipher(msgBuf, cipherType, keyBuf, '');
    },
    desCbcEncrypt: (key, msg, iv) => {
        let msgBuf = Buffer.from(msg, 'hex');
        let keyBuf = Buffer.from(key, 'hex');

        msgBuffAssert(msgBuf, 8);
        let cipherType = getCipherType(['des', 'cbc', keyBuf.length]);

        let ivBuf = (iv && Buffer.from(iv, 'hex')) || Buffer.alloc(8, 0);

        if (ivBuf.length !== 8) {
            throw Error('Invalid initialize vector length, must set to 8');
        }

        return cipher(msgBuf, cipherType, keyBuf, ivBuf);
    },
    desCbcDecrypt: (key, msg, iv) => {
        let msgBuf = Buffer.from(msg, 'hex');
        let keyBuf = Buffer.from(key, 'hex');

        msgBuffAssert(msgBuf, 8);
        let cipherType = getCipherType(['des', 'cbc', keyBuf.length]);

        let ivBuf = (iv && Buffer.from(iv, 'hex')) || Buffer.alloc(8, 0);

        if (ivBuf.length !== 8) {
            throw Error('Invalid initialize vector length, must set to 8');
        }

        return decipher(msgBuf, cipherType, keyBuf, ivBuf);
    }
};
