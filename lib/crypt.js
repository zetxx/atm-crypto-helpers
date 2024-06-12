const crypto = require('crypto');
const cmac = require('ut-function.cmac');

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
    let op = crypto.createCipheriv(cipherType, key, iv);
    op.setAutoPadding(false);
    return op.update(msg).toString('hex').toUpperCase();
};

const decipher = (msg, cipherType, key, iv) => {
    let op = crypto.createDecipheriv(cipherType, key, iv);
    op.setAutoPadding(false);
    return op.update(msg).toString('hex').toUpperCase();
};

module.exports = {
    aesEcbEncrypt: (key, msg) => {
        let msgBuf = Buffer.from(msg, 'hex');
        let keyBuf = Buffer.from(key, 'hex');

        msgBuffAssert(msgBuf, 16);
        let cipherType = getCipherType(['aes', 'ecb', keyBuf.length]);

        return cipher(msgBuf, cipherType, keyBuf, '');
    },
    desEcbEncrypt: (key, msg) => {
        let msgBuf = Buffer.from(msg, 'hex');
        let keyBuf = Buffer.from(key, 'hex');

        msgBuffAssert(msgBuf, 8);
        let cipherType = getCipherType(['des', 'ecb', keyBuf.length]);

        return cipher(msgBuf, cipherType, keyBuf, '');
    },
    desEcbDecrypt: (key, msg) => {
        let msgBuf = Buffer.from(msg, 'hex');
        let keyBuf = Buffer.from(key, 'hex');

        msgBuffAssert(msgBuf, 8);
        let cipherType = getCipherType(['des', 'ecb', keyBuf.length]);

        return decipher(msgBuf, cipherType, keyBuf, '');
    },
    keyblockDecrypt: (key, data) => {
        // key structure:
        // - keyLength - 4 characters
        // - key - keyLength characters
        // - key mac - 16 characters
        const keyLength = parseInt(data.slice(0, 4));
        const keyEncrypted = data.slice(4, 4 + keyLength);
        const iv = data.slice(4 + keyLength);
        const kbek1 = cmac(key, '0100000000000080', 'des3');
        const kbek2 = cmac(key, '0200000000000080', 'des3');
        const decipher = crypto.createDecipheriv('des-ede3-cbc', Buffer.from((kbek1 + kbek2 + kbek1), 'hex'), Buffer.from(iv, 'hex'));
        decipher.setAutoPadding(false);
        let decrypted = decipher.update(keyEncrypted, 'hex', 'hex');
        decrypted += decipher.final('hex');
        const decryptedKeyLength = Number.parseInt(decrypted.slice(0, 4), 16) / 4; // length is hexadecimal in bits
        return decrypted.slice(4, 4 + decryptedKeyLength).toUpperCase();
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
