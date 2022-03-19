// 两个大质数，这里为了便于理解，选择小的，实际是1024位或者2048位的大质数
let p = 3;
let q = 11;
let N = p * q; // 数学上无法实现根据N求出p和q
let r = (p - 1) * (q - 1); // 欧拉公式
let e = 7; // 挑选一个指数
// 秘钥是怎么来的，其中的一个算法
let d = 1;
while ((e * d) % r !== 1) {
  d++;
}
console.log("求出私钥中的d", d); // 3
// 公钥 + 私钥
const publicKey = { e, N };
const privateKey = { d, N };
// 加密方法
function encrypt(data) {
  return Math.pow(data, publicKey.e) % publicKey.N;
}
// 解密方法
function decrypt(data) {
  return Math.pow(data, privateKey.d) % privateKey.N;
}
// 加密
let data = 5;
let secret = encrypt(data);
console.log("加密之后的数据", secret);
// 解密
let originData = decrypt(secret);
console.log("解密之后的数据", originData);
