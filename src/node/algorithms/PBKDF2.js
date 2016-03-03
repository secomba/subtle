var crypto = require('crypto');

var PBKDF2 = {
    checkParams: function(format, algorithm) {
        return format === "raw" && algorithm.name === "PBKDF2";
    },

    usages: {'deriveBits': 'deriveBits'},

    formats: {
        raw: {
            types: [
                {
                    label: 'deriveBits',
                    usage: {
                        deriveBits: function(key, algorithm) {
                            return function(options, length) {
                                return PBKDF2.deriveBits(key, options, length);
                            };
                        }
                    }
                }
            ],

            import: function(key, algorithm) {
                return new Buffer(key);
            }
        }
    },

    createExporter: function(type, key) {
        throw "not implemented";
    },

    deriveBits: function(key, options, length) {
        var method = {"SHA-512": "sha512", "SHA-256": "sha256"}[options.hash.name];

        var salt = new Buffer(options.salt);
        return PBKDF2.pbkdf2(key, salt, options.iterations, length / 8, method)
        .then(function(result) {
            var nativeResult = new Uint8Array(result.length);
            for (var i = 0; i < result.length; i++) {
                nativeResult[i] = result[i];
            }
            return nativeResult;
        });
    },

    _combineBufferAndInteger: function(buffer, integer) {
        var result = new Buffer(buffer.length + 4);
        for (var i = 0; i < buffer.length; i++) {
            result[i] = buffer[i];
        }
        result[buffer.length + 0] = (integer >> 24) & 0xff;
        result[buffer.length + 1] = (integer >> 16) & 0xff;
        result[buffer.length + 2] = (integer >> 8)  & 0xff;
        result[buffer.length + 3] = (integer >> 0)  & 0xff;
        return result;
    },

    _F_partial_with_timeout: function(keyString, count, u, method) {
        return new Promise(function(resolve) {
            var result = new Buffer({'sha256': 32, 'sha512': 64}[method]).fill(0);
            for (var i = 0; i < count; i++) {
                var hmac = crypto.createHmac(method, keyString);
                hmac.update(u);
                u = hmac.digest();
                for (var k = 0; k < result.length; k++) {
                    result[k] ^= u[k];
                }
            }
            setTimeout(function() {
                resolve({
                    uXor: result,
                    uLast: u
                });
            }, 1);
        });
    },

    _F: function(keyString, salt, iterations, index, method) {
        var result = new Buffer({'sha256': 32, 'sha512': 64}[method]).fill(0);
        var u = PBKDF2._combineBufferAndInteger(salt, index);

        function nextIterations(iterationsLeft) {
            var iterationBlock = Math.min(iterationsLeft, 200);

            if (iterationBlock > 0) {
                return PBKDF2._F_partial_with_timeout(keyString, iterationBlock, u, method)
                .then(function(partialResult) {
                    u = partialResult.uLast;
                    for (var i = 0; i < result.length; i++) {
                        result[i] ^= partialResult.uXor[i];
                    }
                    return nextIterations(iterationsLeft - iterationBlock);
                });
            } else {
                return Promise.resolve();
            }
        }

        return nextIterations(iterations)
        .then(function() {
            return result;
        });
    },

    pbkdf2: function(keyString, salt, iterations, length, method) {
        var result = new Buffer(length);

        function continueAtOffset(offset, index) {
            if (offset < result.length) {
                return PBKDF2._F(keyString, salt, iterations, index, method)
                .then(function(byteBlock) {
                    for (var i = offset, k = 0; k < byteBlock.length && i < result.length; i++, k++) {
                        result[i] = byteBlock[k];
                    }
                    return continueAtOffset(offset + byteBlock.length, index + 1);
                });
            } else {
                return Promise.resolve();
            }
        }

        return continueAtOffset(0, 1)
        .then(function() {
            return result;
        });
    }
};

module.exports = PBKDF2;
