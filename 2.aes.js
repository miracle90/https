let crypto = require("crypto");
/**
 *
 * @param {*} data 数据
 * @param {*} key 秘钥
 * @param {*} iv 向量，相当于加盐
 */
function encrypt(data, key, iv) {
  let cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
  cipher.update(data); // 把内容传给实例
  return cipher.final("hex"); // 把结果输出成16进制的字符串
}
function decrypt(data, key, iv) {
  let cipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  cipher.update(data, "hex"); // 加密是16进制，解密也需要16进制
  return cipher.final("utf8"); // 原来是utf-8
}
let message = "abc";
let key = "1234567890123456";
let iv = "6543210987654321";
let data = encrypt(message, key, iv);
console.log(data);
let decryptData = decrypt(data, key, iv);
console.log(decryptData);

// md5和sha1都已经被破解
