var pbkdf2 = {
    sha256: require("pbkdf2-sha256"),
    sha512: require("pbkdf2-sha512")
};

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

        key = key.toString('utf8');
        var salt = new Buffer(options.salt).toString('utf8'); // TODO: make this work without string-encodings
        var result = pbkdf2[method](key, salt, options.iterations, length / 8);
        var nativeResult = new Uint8Array(result.length);
        for (var i = 0; i < result.length; i++) {
            nativeResult[i] = result[i];
        }
        return nativeResult;
    }
};

module.exports = PBKDF2;
