var forge = require("node-forge")
var Hashes = require("jshashes")
var subtleToForge = {
  "SHA-1" : "sha1",
  "SHA-256" : "sha256",
  "SHA-512" : "sha512"
}

var digest = function digest(alg, data){
  if (!subtleToForge[alg.name])
    return Promise.reject("unsupported hashing algorithm")
  else{
      if (alg.name === "SHA-512") {
          // special treatment, not covered by this forge version
          return new Buffer(new Hashes.SHA512().hex(data.toString("binary")), "hex");
      } else {
          var md = forge.md[subtleToForge[alg.name]].create()
          md.update(data.toString("binary"))

          return new Buffer(md.digest().bytes(), "binary")
      }
  }
};

module.exports = digest;
