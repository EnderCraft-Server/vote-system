/* 工作量证明求解器（hashcash 思路）：找 counter，使 sha256(salt + ":" + counter)
   至少有 bits 个前导零比特。

   为什么是手写 SHA-256 而不是 crypto.subtle：
   一次 subtle.digest 是异步调用，每算一个 hash 都要 await，实测只有几万次/秒，
   手机端一次 18 位挑战要几十秒（24 位要几十分钟）。这里消息长度固定
   （salt + ':' + counter ≤ 47 字节 → 永远 1 个 64 字节块），
   所以每个 hash 就是一次块压缩 + 一次 clz32 判断，能跑到百万次/秒。
*/
"use strict";

var K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

var H0 = new Int32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

function compress(H, W, buf) {
  var i, t;
  for (i = 0; i < 16; i++) {
    t = i << 2;
    W[i] = (buf[t] << 24) | (buf[t + 1] << 16) | (buf[t + 2] << 8) | buf[t + 3];
  }
  for (i = 16; i < 64; i++) {
    var w15 = W[i - 15], w2 = W[i - 2];
    var s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    var s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
  for (i = 0; i < 64; i++) {
    var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    var ch = (e & f) ^ (~e & g);
    var t1 = (h + S1 + ch + K[i] + W[i]) | 0;
    var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    var maj = (a & b) ^ (a & c) ^ (b & c);
    var t2 = (S0 + maj) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0;
    d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
  H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
}

self.onmessage = function (ev) {
  var d = ev.data || {};
  var salt = String(d.salt || "");
  var bits = d.bits | 0;
  if (!salt || bits <= 0 || bits > 32) {
    self.postMessage({ ok: false, error: "bad challenge" });
    return;
  }

  var buf = new Uint8Array(64);
  var base = 0;
  for (var i = 0; i < salt.length && base < 47; i++) {
    buf[base++] = salt.charCodeAt(i) & 0xff;
  }
  buf[base++] = 58; // ':'

  var H = new Int32Array(8);
  var W = new Int32Array(64);
  var digits = new Uint8Array(10);
  var counter = 0;
  var t0 = Date.now();
  var lastReport = t0;

  for (;;) {
    // 写十进制 counter（倒着取余再反着拷）
    var n = 0, v = counter;
    do {
      digits[n++] = 48 + (v % 10);
      v = (v / 10) | 0;
    } while (v > 0);
    var end = base + n;
    for (var k = 0; k < n; k++) buf[base + k] = digits[n - 1 - k];

    // 补位：0x80 + 零填充 + 64 位大端长度
    buf[end] = 0x80;
    for (k = end + 1; k < 56; k++) buf[k] = 0;
    var bitLen = end << 3;
    buf[56] = 0; buf[57] = 0; buf[58] = 0; buf[59] = 0;
    buf[60] = (bitLen >>> 24) & 0xff;
    buf[61] = (bitLen >>> 16) & 0xff;
    buf[62] = (bitLen >>> 8) & 0xff;
    buf[63] = bitLen & 0xff;

    H[0] = H0[0]; H[1] = H0[1]; H[2] = H0[2]; H[3] = H0[3];
    H[4] = H0[4]; H[5] = H0[5]; H[6] = H0[6]; H[7] = H0[7];
    compress(H, W, buf);

    // 前导零：先看 H[0]，全零再看 H[1]（bits ≤ 32，最多看两字）
    var z = Math.clz32(H[0]);
    if (z === 32) z += Math.clz32(H[1] === 0 ? 0 : H[1]);
    if (z >= bits) {
      self.postMessage({ ok: true, counter: counter, hashes: counter + 1, ms: Date.now() - t0 });
      return;
    }

    counter++;
    if ((counter & 8191) === 0) {
      var now = Date.now();
      if (now - lastReport >= 120) {
        lastReport = now;
        var elapsed = now - t0;
        self.postMessage({
          progress: counter,
          hashes: counter,
          ms: elapsed,
          rate: Math.round(counter / (elapsed / 1000 || 1))
        });
      }
    }
  }
};
