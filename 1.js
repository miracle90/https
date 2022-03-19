let secret = 3;

// 对称加密，加密的秘钥和解密的秘钥是一个
function encrypt(message) {
  // 先变成一个buffer，字节数组
  let buffer = Buffer.from(message);
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = buffer[i] + secret;
  }
  return buffer.toString();
}

let message = "abc";

const res = encrypt(message);
console.log(res)

function decrypt(message) {
  let buffer = Buffer.from(message);
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = buffer[i] - secret;
  }
  return buffer.toString();
}

const decryptRes = decrypt(res);
console.log(decryptRes)
