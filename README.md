---
theme: cyanosis
---

### 相关概念

1. http的痛点
1. SSL/TLS
1. 对称加密（AES、DES）
1. 非对称加密（RSA、ECC）
1. 哈希（MD5、SHA1、SHA256、加盐）
1. 数字签名（私钥签名，公钥验证签名）
1. 数字证书
1. Diffie-Hellman算法（大质数分解质因数）
1. ECC（椭圆曲线加密算法）
1. ECDHE
1. 秘钥协商（RSA、ECDHE）

# 一、现有http的痛点及https解决方案

| 痛点 | 解决方案 | 描述 |
| - | - | - |
| 窃听 | 加密 | 对称加密AES |
| 秘钥传递 | 秘钥协商 | 非对称加密（RSA和ECDHE） |
| 篡改 | 完整性校验 | 散列算法（md5、sha256）签名 |
| 身份冒充 | CA权威机构 | 散列算法（md5、sha256） + RSA签名 |

# 二、HTTPS中的S到底是什么

![image.png](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/d4bc6f7928db43c1946372b59d961687~tplv-k3u1fbpfcp-watermark.image?)

# 三、对称加密

-   对称加密是最快速、最简单的一种加密方式,加密(encryption)与解密(decryption)用的是同样的密钥(secret key)
-   主流的有`AES`和`DES`

### 1. 简单实现

-   消息 `abc`
-   密钥 3
-   密文 def

![image.png](https://p1-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/fd30b0712ff64450873a929389897ca8~tplv-k3u1fbpfcp-watermark.image?)

### 2. 代码实现

```js
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
```

### 3. AES

-   algorithm用于指定加密算法，如aes-128-ecb、aes-128-cbc等（类型+长度+模式）
-   key是用于加密的密钥
-   iv参数用于指定加密时所用的向量（随机变量）

> 如果加密算法是128，则对应的密钥和向量必须是16位，加密算法是256，则对应的密钥和向量必须是32位

![image.png](https://p6-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/67bbcdc469984fe8b6c0781ff78daf83~tplv-k3u1fbpfcp-watermark.image?)

##### AES应用

```js
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
```

# 四、非对称加密

> 对称加密的痛点：互联网上没有办法安全的交换密钥

### 1 单向函数

- 单向函数顺向计算起来非常的容易，但求逆却非常的困难
- 也就是说，已知x，我们很容易计算出f(x)。但已知f(x)，却很难计算出x
- 例如：两瓶饮料倒在一起很容易合成，但分解很难，非对称加密原理基于此

### 2 RSA算法

[RSA算法详解](https://juejin.cn/post/6844903559582973959)

我们知道像RSA这种非对称加密算法很安全，那么到底为啥子安全呢？ 

- m：要加密的数据
-   *p,q*：我们随机挑选的两个大质数；
-   *N*：是由两个大质数*p*和*q*相乘得到的。*N = p * q*；
-   *e*：随机选择和和*r*互质的数字，实际中通常选择65537；
- c：加密之后的数据
-   *r*：由欧拉函数得到的*N*的值，*r = φ(N) = φ(p)φ(q) = (p-1)(q-1)* 。
-   *d*： d是以欧拉定理为基础求得的e关于r的模反元素，*ed = 1 (mod r)* ；

![image.png](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/34a564bf3d9b4155acffd1c944269f52~tplv-k3u1fbpfcp-watermark.image?)

#### d的计算公式

```js
let d = 1;
while ((e * d) % r !== 1) {
  d++;
}
console.log("求出私钥中的d", d); // 3
```

*N*和*e*我们都会公开使用，最为重要的就是私钥中的*d*，*d*一旦泄露，加密也就失去了意义。那么得到d的过程是如何的呢？如下:

1.  比如知道e和r，因为d是e关于r的模反元素；r是φ(N) 的值
1.  而*φ(N)=(p-1)(q-1)* ，所以知道p和q我们就能得到d;
1.  *N = pq*，从公开的数据中我们只知道N和e，所以问题的关键就是对N做因式分解能不能得出p和q

> 核心原理：将p和q相乘得出乘积N很容易，但要是想要通过乘积N推导出p和q极难。即对两个大质数相乘得到的一个数进行因式分解极难

目前公开破译的位数是768位，实际使用一般是1024位或是2048位，所以理论上特别的安全。

#### 代码实现

```js
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
console.log("加密之后的数据", secret); // 14
// 解密
let originData = decrypt(secret);
console.log("解密之后的数据", originData); // 5
```

### 3. RSA的应用

* 生成一对秘钥对
* 私钥加密
* 公钥解密

```js
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
```

# 五、哈希

hash => 切碎的食物

![image.png](https://p6-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/25aac1eaf56142308f28b0649f8ad9a2~tplv-k3u1fbpfcp-watermark.image?)

### 1. 哈希函数

哈希函数的作用是给一个任意长度的数据生成出一个固定长度的数据

-   安全性：可以从给定的数据X计算出哈希值Y，但不能从哈希值Y计算机数据X
-   独一无二：不同的数据一定会产出不同的哈希值
-   长度固定：不管输入多大的数据,输出长度都是固定的

### 2. 哈希碰撞

-   所谓哈希(hash),就是将不同的输入映射成独一无二的、固定长度的值（又称"哈希值"）。它是最常见的软件运算之一
-   如果不同的输入得到了同一个哈希值,就发生了哈希碰撞(collision)
-   防止哈希碰撞的最有效方法，就是扩大哈希值的取值空间
-   16个二进制位的哈希值，产生碰撞的可能性是 65536 分之一。也就是说，如果有65537个用户，就一定会产生碰撞。哈希值的长度扩大到32个二进制位，碰撞的可能性就会下降到 `4,294,967,296` 分之一

```js
console.log(Math.pow(2, 16));//65536
console.log(Math.pow(2, 32));//42亿
```

### 3 哈希分类

-   哈希还可以叫摘要(digest)、校验值(chunkSum)和指纹(fingerPrint)
-   如果两段数据完全一样,就可以证明数据是一样的
-   哈希有二种
    -   普通哈希用来做完整性校验，流行的是MD5
    -   加密哈希用来做加密,目前最流行的加密算法是 SHA256( Secure Hash Algorithm) 系列

### 4. hash使用

#### 4.1 简单哈希

```js
function hash(input) {
    return input % 1024;
}
let r1 = hash(100);
let r2 = hash(1124);
console.log(r1, r2);
```

#### 4.2 md5

MD5 Message-Digest Algorithm）

实现原理：数据填充 + 添加消息长度 + 分组处理

1.  首先将消息以512位为一分组进行处理，分为N组
1.  将每组消息N(i)进行4轮变换（四轮主循环），以上面所说4个常数首先赋值给a、b、c、d为起始变量进行计算，重新输出4个变量，并重新赋值给a、b、c、d四个值。
1.  以第2步获得的新的a、b、c、d四个值，再进行下一分组的运算，如果已经是最后一个分组，则这4个变量的最后结果按照从低内存到高内存排列起来，共128位，这就是MD5算法的输出。

```js
var crypto = require('crypto');
var content = '123456';
var result = crypto.createHash('md5').update(content).digest("hex")
console.log(result);//32位十六进制 = 128位二进制
```

#### 4.3 sha256

```js
const salt = '123456';
const sha256 = str => crypto.createHmac('sha256', salt)
    .update(str, 'utf8')
    .digest('hex')

let ret = sha256(content);
console.log(ret);//64位十六进制 = 256位二进制
```

# 六、 数字签名

数字签名的基本原理是用私钥去签名，而用公钥去验证签名

![image.png](https://p6-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/56446ab2dc8b4fbc8487b51455f721af~tplv-k3u1fbpfcp-watermark.image?)

![image.png](https://p1-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/e104eb64cc7b44efb0604f31ed9b4bc1~tplv-k3u1fbpfcp-watermark.image?)

```js
const {
  generateKeyPairSync,
  createSign,
  createVerify,
} = require("crypto");

/**
 * 数字签名和数字证书的过程
 */
const rsa = generateKeyPairSync("rsa", {
  modulusLength: 1024,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
    cipher: "aes-256-cbc",
    passphrase: "passphrase", // 私钥的密码
  },
});

const file = "file";
// 先创建签名对象
const signObj = createSign("RSA-SHA256");
// 放入文件内容
signObj.update(file);
// 用rsa私钥签名，输出一个16进制的字符串
let sign = signObj.sign({
  key: rsa.privateKey,
  format: "pem",
  passphrase: "passphrase",
});
console.log(sign);
// 创建验证签名对象
const verifyObj = createVerify("RSA-SHA256");
// 放入文件内容
verifyObj.update(file);
// 验证签名是否合法
let isValid = verifyObj.verify(rsa.publicKey, sign, "hex");
console.log(isValid);

// 内部是这样实现的
// 1、先拿到文件file
// 2、用 publicKey 计算签名 sign
// 3、如果跟对方的sign匹配，验证通过
```

# 七、 数字证书

数字证书是一个由可信的第三方发出的，用来证明所有人身份以及所有人拥有某个公钥的电子文件

一个数字证书通常包含了：

-   公钥；
-   持有者信息；
-   证书认证机构（CA）的信息；
-   CA 对这份文件的数字签名及使用的算法；
-   证书有效期；
-   还有一些其他额外信息；

![image.png](https://p6-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/590c640555d0456f8230ec49810ce6d2~tplv-k3u1fbpfcp-watermark.image?)

### 证书签发

> 直接对内容进行rsa签名，性能太差，先使用摘要算法，根据内容算出一个摘要签名
> 
> 然后再使用rsa算法对摘要签名进行签名

-   首先 CA 会把持有者的公钥、用途、颁发者、有效时间等信息打成一个包，然后对这些信息进行 Hash 计算，得到一个 Hash 值；
-   然后 CA 会使用自己的私钥将该 Hash 值加密，生成 Certificate Signature，也就是 CA 对证书做了签名；
-   最后将 Certificate Signature 添加在文件证书上，形成数字证书；

### 证书校验

-   首先客户端会使用同样的 Hash 算法获取该证书的 Hash 值 H1；
-   通常浏览器和操作系统中集成了 CA 的公钥信息，浏览器收到证书后可以使用 CA 的公钥解密 Certificate Signature 内容，得到一个 Hash 值 H2 ；
-   最后比较 H1 和 H2，如果值相同，则为可信赖的证书，否则则认为证书不可信。

### 证书链



证书的验证过程中还存在一个证书信任链的问题，因为我们向 CA 申请的证书一般不是根证书签发的，而是由中间证书签发的，比如百度的证书，从下图你可以看到，证书的层级有三级：

![image.png](https://p6-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/aa03e5626b634d1da41895be01e5ad58~tplv-k3u1fbpfcp-watermark.image?)

![image.png](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/6acacb0fe30e42ac9c07745b6a138f43~tplv-k3u1fbpfcp-watermark.image?)


* 为什么需要证书链这么麻烦的流程？Root CA 为什么不直接颁发证书，而是要搞那么多中间层级呢？

这是为了确保根证书的绝对安全性，将根证书隔离地越严格越好，不然根证书如果失守了，那么整个信任链都会有问题。


# 八、Diffie-Hellman算法

Diffie-Hellman算法是一种密钥交换协议，它可以让双方在不泄漏密钥的情况下协商出一个密钥来

Diffie-Hellman算法是非对称加密算法，该算法的核心数学思想是**离散对数**。

![image.png](https://p1-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/48c344bc39284fae947cf00d634c50aa~tplv-k3u1fbpfcp-watermark.image?)

上图的，底数 a 和模数 p 是离散对数的公共参数，也就说是公开的，b 是真数，i 是对数。知道了对数，就可以用上面的公式计算出真数。但反过来，知道真数却很难推算出对数。

**特别是当模数 p 是一个很大的质数，即使知道底数 a 和真数 b ，在现有的计算机的计算水平是几乎无法算出离散对数的，这就是 DH 算法的数学基础。**

![image.png](https://p6-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/cc4d59f58c6e4bd39c731b23ba7902e1~tplv-k3u1fbpfcp-watermark.image?)

### 1. 实现原理的伪代码

```js
let N = 23; // 公共
let p = 5;
let secret1 = 6;

let A = Math.pow(p, secret1) % N;
console.log(`p=${p}; N=${N}; A=${A};`);

let secret2 = 15;
let B = Math.pow(p, secret2) % N;
console.log(`p=${p}; N=${N}; B=${B};`);

// A将A、p、N给B
// B计算后将B给A
// 这样A拥有，A、B、p、N、secret1
// 这样B拥有，A、B、p、N、secret2

// A这样计算的
console.log(Math.pow(B, secret1) % N);
// B这样计算的
console.log(Math.pow(A, secret2) % N);
```

### 2. 使用

```js
const { createDiffieHellman } = require("crypto");
// 客户端
const client = createDiffieHellman(512); // 512字节
// 生成一个秘钥对
const clientKeys = client.generateKeys();
// 生成一个质数
const prime = client.getPrime();
const generator = client.getGenerator();
// 服务器端
const server = createDiffieHellman(prime, generator);
// 生成一个秘钥对
const serverKeys = server.generateKeys();
// 双方生成秘钥
let client_secret = client.computeSecret(serverKeys);
let server_secret = server.computeSecret(clientKeys);
console.log("client_secret", client_secret.toString("hex"));
console.log("server_secret", server_secret.toString("hex"));
```

# 九、ECC

椭圆曲线加密算法(ECC) 是基于椭圆曲线数学的一种公钥加密的算法

![image.png](https://p6-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/7e8e0709546e4039a4f97d45a7ef639f~tplv-k3u1fbpfcp-watermark.image?)

其中涉及的数学知识过于复杂，此处省略。。。

只要记住与传统的基于大质数因子分解困难性的加密方法不同，ECC通过椭圆曲线方程式的性质产生密钥

### ECC vs RSA 对比

![image.png](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/7dd1cb18a5bb46838cfdd1f7d1c6ee22~tplv-k3u1fbpfcp-watermark.image?)

### ECC缺点

* 设计困难，实现复杂

# 十、ECDHE

ECDHE 是使用椭圆曲线（ECC）的 DH（Diffie-Hellman）算法，ECDHE 算法是在 DHE 算法的基础上利用了 ECC 椭圆曲线特性，可以用更少的计算量计算出公钥，以及最终的会话密钥。


> ### 关键概念
> * 椭圆曲线：公开的
> * 基点G：公开的
> * 生成一个随机数d，做为私钥（d1，d2）
> * 计算得到公钥Q（Q=dG）
> * 交换公钥
> * 计算点 (x, y) = dQ
> * x坐标是一样的，所以它是共享密钥，也就是会话密钥

小红和小明使用 ECDHE 密钥交换算法的过程：

-   双方事先确定好使用哪种椭圆曲线，和曲线上的基点 G，这两个参数都是公开的；
-   双方各自随机生成一个随机数作为**私钥d**，并与基点 G相乘得到**公钥Q**（Q = dG），此时小红的公私钥为 Q1 和 d1，小明的公私钥为 Q2 和 d2；
-   双方交换各自的公钥，最后小红计算点（x1，y1） = d1Q2，小明计算点（x2，y2） = d2Q1，由于椭圆曲线上是可以满足乘法交换和结合律，所以 d1Q2 = d1d2G = d2d1G = d2Q1 ，因此**双方的 x 坐标是一样的，所以它是共享密钥，也就是会话密钥**。

这个过程中，双方的私钥都是随机、临时生成的，都是不公开的，即使根据公开的信息（椭圆曲线、公钥、基点 G）也是很难计算出椭圆曲线上的离散对数（私钥）。

# 十一、 秘钥协商

### 1. RSA秘钥协商

传统的 TLS 握手基本都是使用 RSA 算法来实现密钥交换的，在将 TLS 证书部署服务端时，证书文件中包含一对公私钥，其中公钥会在 TLS 握手阶段传递给客户端，私钥则一直留在服务端，一定要确保私钥不能被窃取。

在 RSA 密钥协商算法中，客户端会生成随机密钥，并使用服务端的公钥加密后再传给服务端。根据非对称加密算法，公钥加密的消息仅能通过私钥解密，这样服务端解密后，双方就得到了相同的密钥，再用它加密应用消息。

> #### 第一次握手
> * **Client Hello**：`发送TLS版本号` + `随机数（Client Random）`+ `支持的密码套件列表`
> #### 第二次握手
> * **Server Hello**：`确认TLS版本号` + `随机数（Server Random）`+ `选择一个密码套件`（如：TLS_RSA_WITH_AES_128_GCM_SHA256）
>    * 密码套件格式：「密钥交换算法 + 签名算法 + 对称加密算法 + 摘要算法」
>    * 由于 WITH 单词只有一个 RSA，则说明握手时密钥交换算法和签名算法都是使用 RSA；
>    * 握手后的通信使用 AES 对称算法，密钥长度 128 位，分组模式是 GCM；
>    * 摘要算法 SHA256 用于消息认证和产生随机数；
> * **Certificate**：`发送证书`
> * **Server Hello Done**：告诉客户端，该发的东西都发了
> #### 第三次握手
> * **Change Cipher Key Exchange**：客户端就会生成一个新的随机数 `pre-master`，用服务器的 RSA 公钥加密该随机数
>    * 至此：客户端和服务端双方都共享了三个随机数，分别是 `Client Random`、`Server Random`、`pre-master`
>    * 双方根据已经得到的三个随机数，生成`会话密钥（Master Secret）`，它是对称密钥，用于对后续的 HTTP 请求/响应的数据加解密。
> * **Change Cipher Spec**：生成完会话密钥后，然后客户端发一个Change Cipher Spec，告诉服务端开始使用加密方式发送消息
> * **Encrypted Handshake Message**：客户端把之前所有发送的数据做个摘要，再用会话密钥（master secret）加密一下，让服务器做个验证，验证加密通信是否可用和之前握手信息是否有被中途篡改过
>    * 可以发现，Change Cipher Spec之前传输的 TLS 握手数据都是明文，之后都是对称密钥加密的密文
> #### 第四次握手
> * **Change Cipher Spec**
> * **Encrypted Handshake Message**

![image.png](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/8644faece94a4262a519514b11ad293e~tplv-k3u1fbpfcp-watermark.image?)

#### RSA 算法的缺陷

使用 RSA 密钥协商算法的最大问题是**不支持前向保密**。因为客户端传递随机数（用于生成对称加密密钥的条件之一）给服务端时使用的是公钥加密的，服务端收到到后，会用私钥解密得到随机数。所以一旦服务端的私钥泄漏了，过去被第三方截获的所有 TLS 通讯密文都会被破解。

为了解决这一问题，于是就有了 ECDHE 密钥协商算法。

### 2. ECDHE秘钥协商

> #### 第一次握手
> * **Client Hello**：`客户端使用的 TLS 版本号`、`支持的密码套件列表`、`随机数（Client Random）`
> #### 第二次握手
> * **Server Hello**：`确认的 TLS 版本号`，`随机数（Server Random）`，`选择的密码套件`
>     * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
>     * 密钥协商算法使用 ECDHE；
>     * 签名算法使用 RSA；
>     * 握手后的通信使用 AES 对称算法，密钥长度 256 位，分组模式是 GCM；
>     * 摘要算法使用 SHA384；
> * **Certificate**
> * **server key change**：`椭圆曲线`、`椭圆曲线基点 G`、`服务端的椭圆曲线公钥`
>     * 服务端生成随机数作为服务端椭圆曲线的私钥，保留到本地；
>     * 根据基点 G 和私钥计算出服务端的椭圆曲线公钥，这个会公开给客户端
> * **server hello done**
> * TLS 两次握手就已经完成了，目前客户端和服务端通过明文共享了这几个信息：`Client Random`、`Server Random`、`使用的椭圆曲线`、`椭圆曲线基点 G`、`服务端椭圆曲线的公钥`
> #### 第三次握手
> * 客户端校验证书合法性
> * 客户端会生成一个随机数作为客户端椭圆曲线的私钥，然后再根据服务端前面给的信息，生成客户端的椭圆曲线公钥
> * **Client Key Exchange**：发送`客户端的椭圆曲线公钥`给服务端
> * 至此，双方都有`对方的椭圆曲线公钥`、`自己的椭圆曲线私钥`、`椭圆曲线`、`基点 G`。于是，双方都就计算出点（x，y），其中 x 坐标值双方都是一样的，前面说 ECDHE 算法时候，说 x 是会话密钥，但实际应用中，x 还不是最终的会话密钥
> * 最终的会话密钥，就是用`客户端随机数` + `服务端随机数` + `x（ECDHE 算法算出的共享密钥）` 三个材料生成的
> * **Change Cipher Spec**：告诉服务端后续改用对称算法加密通信。
> * **Encrypted Handshake Message**：把之前发送的数据做一个摘要，再用对称密钥加密一下，让服务端做个验证，验证下本次生成的对称密钥是否可以正常使用
> #### 第四次握手
> * **New Session Ticket**
> * **Change Cipher Spec**
> * **Encrypted Handshake Message**

### 3. RSA / ECDHE 对比

-   RSA 密钥协商算法「不支持」前向保密（ECDH和DH也不支持），ECDHE 密钥协商算法「支持」前向保密（DHE支持）；
-   使用了 RSA 密钥协商算法，TLS 完成四次握手后，才能进行应用数据传输，而对于 ECDHE 算法，客户端可以不用等服务端的最后一次 TLS 握手，就可以提前发出加密的 HTTP 数据，节省了一个消息的往返时间；
-   使用 ECDHE， 在 TLS 第 2 次握手中，会出现服务器端发出的「Server Key Exchange」消息，而 RSA 握手过程没有该消息；

<hr />

### 扩展问题

* SSL 连接断开后如何恢复?
* 301、302 的 https 被挟持怎么办?
* HTTPS 中间人攻击

#### 1、SSL 连接断开后如何恢复?

一共有两种方法来恢复断开的 SSL 连接，一种是使用 session ID，一种是 session ticket。

1.  使用 session ID 的方式，每一次的会话都有一个编号，当对话中断后，下一次重新连接时，只要客户端给出这个编号，服务器如果有这个编号的记录，那么双方就可以继续使用以前的秘钥，而不用重新生成一把。 目前所有的浏览器都支持这一种方法。 但是这种方法有一个缺点是，session ID 只能够存在一台服务器上，如果我们的请求通过负载平衡被转移到了其他的服务器上，那么就无法恢复对话。
1.  另一种方式是 session ticket 的方式，session ticket 是服务器在上一次对话中发送给客户的，这个 ticket 是加密的，只有服务器能够解密，里面包含了本次会话的信息，比如对话秘钥和加密方法等。 这样不管我们的请求是否转移到其他的服务器上，当服务器将 ticket 解密以后，就能够获取上次对话的信息，就不用重新生成对话秘钥了。

#### 2、301、302 的 https 被挟持怎么办?

首先，301是永久重定向，302是临时重定向。

一般301使用的情况有：

1.http网站跳转到https网站

2.二级域名跳转到主域名

3.404页面失效跳转到新的页面

4.老的域名跳转到新的域名

302使用的情况是不太常见的，一般是网站在短时间内改版，在不影响用户体验的 情况下，临时吧页面跳转到临时页面。

因为在将http请求重定向到https的过程中，存在中间人攻击的风险，那么就可能被劫持。解决该问题的方案为采用HSTS策略，通过307 Internal Redirect来代替301 Move Permanently。

* 合理使用 HSTS

什么是 HSTS 呢?HSTS(HTTP Strict Transport Security,HTTP 严格传输安全协议)表明网站已经实现了 TLS，要求浏览器对用户明文访问的 URL 重写成了 HTTPS，避免始终强制 302 重定向的延时开销。

* HSTS 的实现原理

当浏览器第一次 HTTP 请求服务器时，返回的响应头中增加`Strict-Transport-Security`，告诉浏览器指定时间内，这个网站必须通过 HTTPS 协议来访问。也就是对于这个网站的 HTTP 地址，浏览器需要现在本地替换为 HTTPS 之后再发送请求。

#### 3、HTTPS 中间人攻击

中间人攻击过程如下：

1.  服务器向客户端发送公钥；
1.  攻击者截获公钥，保留在自己手上；
1.  然后攻击者自己生成一个【伪造的】公钥，发给客户端；
1.  客户端收到伪造的公钥后，生成加密 hash（秘钥） 值发给服务器；
1.  攻击者获得加密 hash 值，用自己的私钥解密获得真秘钥；
1.  同时生成假的加密 hash 值，发给服务器；
1.  服务器用私钥解密获得假秘钥；
1.  服务器用假秘钥加密传输信息；

防范方法：

服务器在发送浏览器的公钥中加入 CA 证书，浏览器可以验证 CA 证书的有效性；（现有 HTTPS 很难被劫持，除非信任了劫持者的 CA 证书）。

<hr />

### 参考链接

* [TLS/SSL 协议详解 (30) SSL中的RSA、DHE、ECDHE、ECDH流程与区别](https://blog.csdn.net/PUSONG568/article/details/81008022)
* [为了搞懂 HTTPS，我把大学的数学书拿了出来。。。](https://juejin.cn/post/6920887234119860232#heading-7)
* [几幅图，拿下 HTTPS](https://juejin.cn/post/6917224067032416263#heading-0)
* [ECC椭圆曲线加密算法](https://juejin.cn/post/6844903889284628488#heading-10)

