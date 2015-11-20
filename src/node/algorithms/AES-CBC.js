var sjcl      = require("sjcl")
    , Algorithm = require("./abstract")("AES-CBC")
    , AES       = require("./shared/AES")
    , secret = Algorithm.types.secret.usage

AES(Algorithm);

secret.encrypt = createEncrypt;
secret.decrypt = createDecrypt;

module.exports = Algorithm;

function byteArray2BlockArray(byteArray) {
    var result = new Array(byteArray.length / 4);
    for (var i = 0; i < result.length; i++) {
        result[i] =
            ((byteArray[i * 4] << 24) & 0xff000000) |
            ((byteArray[i * 4 + 1] << 16) & 0xff0000) |
            ((byteArray[i * 4 + 2] << 8) & 0xff00) |
            (byteArray[i * 4 + 3] & 0xff);
    }
    return result;
}

function blockArray2byteArray(blockArray) {
    var result = new Buffer(blockArray.length * 4);
    for (var i = 0; i < result.length; i++) {
        result[i] = (blockArray[Math.floor(i / 4)] >> (24 - (i % 4) * 8)) & 0xff;
    }
    return result;
}

function CRYPT(action, Key, alg, data){
    var iv = byteArray2BlockArray(alg.iv);
    var xorFirstValue = [iv[0], iv[1], iv[2], iv[3]];

    if (action === "encrypt") {
        var aesBlocksize = 16;
        var paddingLength = (aesBlocksize - (data.length % aesBlocksize));
        var padding = new Buffer(paddingLength);
        padding.fill(paddingLength);

        var dataIn4ByteBlocks = byteArray2BlockArray(Buffer.concat([
            data,
            padding
        ]));

        for (var i = 0; i < dataIn4ByteBlocks.length; i += 4) {
            var cryptoInput = [
                dataIn4ByteBlocks[i] ^ xorFirstValue[0],
                dataIn4ByteBlocks[i + 1] ^ xorFirstValue[1],
                dataIn4ByteBlocks[i + 2] ^ xorFirstValue[2],
                dataIn4ByteBlocks[i + 3] ^ xorFirstValue[3]
            ];
            xorFirstValue = Key.encrypt(cryptoInput);
            dataIn4ByteBlocks[i] = xorFirstValue[0];
            dataIn4ByteBlocks[i + 1] = xorFirstValue[1];
            dataIn4ByteBlocks[i + 2] = xorFirstValue[2];
            dataIn4ByteBlocks[i + 3] = xorFirstValue[3];
        }

        return blockArray2byteArray(dataIn4ByteBlocks);
    } else {
        var dataIn4ByteBlocks = byteArray2BlockArray(data);

        for (var i = 0; i < dataIn4ByteBlocks.length; i += 4) {
            var cryptoInput = [
                dataIn4ByteBlocks[i],
                dataIn4ByteBlocks[i + 1],
                dataIn4ByteBlocks[i + 2],
                dataIn4ByteBlocks[i + 3]
            ];
            var decryptedNotXored = Key.decrypt(cryptoInput);
            dataIn4ByteBlocks[i] = decryptedNotXored[0] ^ xorFirstValue[0];
            dataIn4ByteBlocks[i + 1] = decryptedNotXored[1] ^ xorFirstValue[1];
            dataIn4ByteBlocks[i + 2] = decryptedNotXored[2] ^ xorFirstValue[2];
            dataIn4ByteBlocks[i + 3] = decryptedNotXored[3] ^ xorFirstValue[3];
            xorFirstValue = cryptoInput;
        }

        var byteDecryptedPadded = blockArray2byteArray(dataIn4ByteBlocks);
        var paddingLength = byteDecryptedPadded[byteDecryptedPadded.length - 1];
        return byteDecryptedPadded.slice(0, byteDecryptedPadded.length - paddingLength);
    }
}
function createEncrypt(Key){
    return function ENCRYPT_AES_CBC(alg, data){
        return CRYPT("encrypt", Key, alg, data);
    };
}

function createDecrypt(Key){
    return function DECRYPT_AES_CBC(alg,data ){
        return CRYPT("decrypt", Key, alg, data);
    }
}

function checkParams(){
    return;
}
