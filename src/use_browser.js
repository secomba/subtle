require("./forge.min.js")
var importKey = require("./node/importKey")

function tryBrowser (routine, arguments){
    return new Promise(function(resolve, reject) {
        var result = crypto.subtle[routine].apply(crypto.subtle, arguments);
        if (routine === "importKey") {
            // importKey is difficult: The import-operation might succeed, while the the usage of the key
            // might fail - in which case we need the JS-equivalent. Therefore, we're adding this here.
            return Promise.all([result, importKey.apply(importKey, arguments)])
            .then(function (results) {
                resolve({webcryptoKey: result[0], jsKey: result[1]});
            })
            .catch(reject);
        } else {
            resolve(result);
        }
    });
}

module.exports = tryBrowser
