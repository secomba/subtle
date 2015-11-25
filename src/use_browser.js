require("./forge.min.js")
var importKey = require("./node/importKey")

function tryBrowser (routine, arguments){
    const tryBrowserArguments = [].slice.call(arguments);
    return new Promise(function(resolve, reject) {
        var result = crypto.subtle[routine].apply(crypto.subtle, tryBrowserArguments);
        if (routine === "importKey") {
            // importKey is difficult: The import-operation might succeed, while the the usage of the key
            // might fail - in which case we need the JS-equivalent. Therefore, we're adding this here.
            for (var i = 0; i < tryBrowserArguments.length; i++) {
                if (tryBrowserArguments[i] instanceof Uint8Array) {
                    tryBrowserArguments[i] = new Buffer(tryBrowserArguments[i]);
                }
            }
            return Promise.all([result, importKey.apply(importKey, tryBrowserArguments)])
            .then(function (results) {
                resolve({webcryptoKey: results[0], jsKey: results[1]});
            })
            .catch(reject);
        } else {
            result.then(resolve).catch(reject);
        }
    });
}

module.exports = tryBrowser
