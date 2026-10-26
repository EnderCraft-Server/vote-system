/* 工作量证明求解器：在 Worker 里算，避免卡住主线程。
   目标：找一个 counter，使 sha256(salt + ":" + counter) 至少有 bits 个前导零比特。 */
"use strict";

function leadingZeroBits(bytes) {
  var n = 0;
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    if (b === 0) { n += 8; continue; }
    var cnt = 0;
    for (var mask = 0x80; mask > 0 && (b & mask) === 0; mask >>= 1) cnt++;
    return n + cnt;
  }
  return n;
}

self.onmessage = async function (event) {
  var data = event.data || {};
  var salt = data.salt, bits = data.bits;
  var enc = new TextEncoder();
  var counter = 0;
  var CHUNK = 256;
  try {
    for (;;) {
      for (var i = 0; i < CHUNK; i++, counter++) {
        var digest = await crypto.subtle.digest("SHA-256", enc.encode(salt + ":" + counter));
        if (leadingZeroBits(new Uint8Array(digest)) >= bits) {
          self.postMessage({ ok: true, counter: counter });
          return;
        }
      }
      self.postMessage({ progress: counter });
    }
  } catch (err) {
    self.postMessage({ ok: false, error: String(err) });
  }
};
