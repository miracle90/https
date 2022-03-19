const {
  generateKeyPairSync,
  privateEncrypt,
  publicDecrypt,
} = require("crypto");
// 生成一对秘钥：公钥 + 私钥
let rsa = generateKeyPairSync("rsa", {
  modulusLength: 1024,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
    cipher: "aes-256-cbc",
    passphrase: "passphrase",
  },
});
let message = "hello";
// 私钥加密后的数据
let encryptMessage = privateEncrypt(
  {
    key: rsa.privateKey,
    passphrase: "passphrase",
  },
  Buffer.from(message, "utf8")
);
console.log("私钥加密后的数据", encryptMessage);
let decryptedMessage = publicDecrypt(rsa.publicKey, encryptMessage);
console.log("公钥解密后的数据", decryptedMessage.toString());
