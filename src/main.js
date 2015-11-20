var Browser = require("./use_node.js")
var OPS = ["generateKey", "importKey", "exportKey", "sign", "verify", "encrypt", "decrypt", "digest", "deriveKey", "deriveBits"]
var nonce = require("crypto").randomBytes(64).toString("hex")
global.FORGE = require("./forgeless.js")
global.Promise =  require("polyfill-promise")
var Subtle = {}
var JS = {}
JS.generateKey = require("./node/generateKey")
JS.importKey = require("./node/importKey")
JS.exportKey = require("./node/exportKey")
JS.sign = require("./node/sign")
JS.verify = require("./node/verify")
JS.encrypt = require("./node/encrypt")
JS.decrypt = require("./node/decrypt")
JS.digest = require("./node/digest")
JS.deriveKey = require("./node/deriveKey")
JS.deriveBits = require("./node/deriveBits")

function makeArgArray (args){
  var ar = []
  for (var i = 0; i < args.length;i++)
    ar.push(Bufferize(args[i]))

  ar.push(nonce);
  return ar;
}

function Bufferize (result){
  if (result instanceof ArrayBuffer)
    result = new Uint8Array(result);
  if (result instanceof Uint8Array)
    result = new Buffer(result);

  return result;
}
function makeRoutine(routine){
  return function(){
    var routineArgs = makeArgArray(arguments)
    return Browser(routine, arguments).then(Bufferize).catch(function useJScrypto(er){
      ////console.log("BROWSER FAILED",er, routineArgs)
      return (typeof JS[routine] === "function") ? JS[routine].apply(JS[routine],routineArgs)
                                                 : Promise.reject("unsupported operation");
    });
  }
}

for (var i in OPS){
  var routine = OPS[i]
  Subtle[routine] = makeRoutine(routine + "");
}

module.exports = Subtle;
