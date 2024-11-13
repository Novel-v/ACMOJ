/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
// var b64pad  = ''; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
export default function hex_md5(s) {
  return binl2hex(core_md5(str2binl(s), s.length * chrsz));
}
// function b64_md5(s) { return binl2b64(core_md5(str2binl(s), s.length * chrsz)); }
// function str_md5(s) { return binl2str(core_md5(str2binl(s), s.length * chrsz)); }
// function hex_hmac_md5(key, data) { return binl2hex(core_hmac_md5(key, data)); }
// function b64_hmac_md5(key, data) { return binl2b64(core_hmac_md5(key, data)); }
// function str_hmac_md5(key, data) { return binl2str(core_hmac_md5(key, data)); }

/*
 * Perform a simple self-test to see if the VM is working
 */
// function md5_vm_test() {
//   return hex_md5('abc') === '900150983cd24fb0d6963f7d28e17f72';
// }

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length
 */
function core_md5(x, len) {
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a = 1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d = 271733878;

  for (var i = 0; i < x.length; i += 16) {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936);
    d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
    b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
    d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
    c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
    d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
    d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

    a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
    d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
    c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
    b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
    d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
    c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
    d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
    c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
    a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
    d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
    c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
    b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
    d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
    b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
    d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
    c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
    d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
    a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
    d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
    b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844);
    d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
    c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
    d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
    d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
    a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
    d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
    b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return [a, b, c, d];
}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t) {
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
}

function md5_ff(a, b, c, d, x, s, t) {
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}

function md5_gg(a, b, c, d, x, s, t) {
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}

function md5_hh(a, b, c, d, x, s, t) {
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}

function md5_ii(a, b, c, d, x, s, t) {
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Calculate the HMAC-MD5, of a key and some data
 */
// function core_hmac_md5(key, data) {
//   var bkey = str2binl(key);
//   if (bkey.length > 16) bkey = core_md5(bkey, key.length * chrsz);

//   var ipad = Array(16); var opad = Array(16);
//   for (var i = 0; i < 16; i++) {
//     ipad[i] = bkey[i] ^ 0x36363636;
//     opad[i] = bkey[i] ^ 0x5C5C5C5C;
//   }

//   var hash = core_md5(ipad.concat(str2binl(data)), 512 + data.length * chrsz);
//   return core_md5(opad.concat(hash), 512 + 128);
// }

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y) {
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt) {
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert a string to an array of little-endian words
 * If chrsz is ASCII, characters >255 have their hi-byte silently ignored.
 */
function str2binl(str) {
  var bin = [];
  var mask = (1 << chrsz) - 1;
  for (var i = 0; i < str.length * chrsz; i += chrsz) {
    bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (i % 32);
  }
  return bin;
}

/*
 * Convert an array of little-endian words to a string
 */
// function binl2str(bin) {
//   var str = '';
//   var mask = (1 << chrsz) - 1;
//   for (var i = 0; i < bin.length * 32; i += chrsz) { str += String.fromCharCode((bin[i >> 5] >>> (i % 32)) & mask); }
//   return str;
// }

/*
 * Convert an array of little-endian words to a hex string.
 */
function binl2hex(binarray) {
  var hex_tab = hexcase ? '0123456789ABCDEF' : '0123456789abcdef';
  var str = '';
  for (var i = 0; i < binarray.length * 4; i++) {
    str += hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF) +
      hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xF);
  }
  return str;
}

/*
 * Convert an array of little-endian words to a base-64 string
 */
// function binl2b64(binarray) {
//   var tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
//   var str = '';
//   for (var i = 0; i < binarray.length * 4; i += 3) {
//     var triplet = (((binarray[i   >> 2] >> 8 * (i   % 4)) & 0xFF) << 16) |
//                 (((binarray[i + 1 >> 2] >> 8 * ((i + 1) % 4)) & 0xFF) << 8)  |
//                 ((binarray[i + 2 >> 2] >> 8 * ((i + 2) % 4)) & 0xFF);
//     for (var j = 0; j < 4; j++) {
//       if (i * 8 + j * 6 > binarray.length * 32) str += b64pad;
//       else str += tab.charAt((triplet >> 6 * (3 - j)) & 0x3F);
//     }
//   }
//   return str;
// }
// 以下是简约版本的MD5算法

// // 配置变量
// var hexcase = 0;  // 十六进制输出格式：0 - 小写字母，1 - 大写字母
// var chrsz = 8;    // 输入字符的位数：8 - ASCII字符，16 - Unicode字符

// // 默认导出函数，计算字符串的MD5值
// export default function hex_md5(s) {
//   return binl2hex(core_md5(str2binl(s), s.length * chrsz));
// }

// // 核心MD5算法函数
// function core_md5(x, len) {
//   // 填充数据
//   x[len >> 5] |= 0x80 << (len % 32);
//   x[((len + 64 >>> 9) << 4) + 14] = len;

//   // 初始化四个哈希值
//   var a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;

//   // 主循环，每次处理16个32位字
//   for (let i = 0; i < x.length; i += 16) {
//     const [olda, oldb, oldc, oldd] = [a, b, c, d];

//     // 调用md5_rounds函数处理16轮
//     [a, b, c, d] = md5_rounds([a, b, c, d], x, i);

//     // 将本轮结果与上一轮结果相加，防止溢出
//     a = safe_add(a, olda);
//     b = safe_add(b, oldb);
//     c = safe_add(c, oldc);
//     d = safe_add(d, oldd);
//   }
//   return [a, b, c, d];
// }

// // 整合MD5变换操作
// function md5_rounds(state, x, i) {
//   // 定义四个操作函数和对应的位移量
//   const funcs = [
//     { f: (b, c, d) => (b & c) | (~b & d), s: [7, 12, 17, 22] },
//     { f: (b, c, d) => (b & d) | (c & ~d), s: [5, 9, 14, 20] },
//     { f: (b, c, d) => b ^ c ^ d, s: [4, 11, 16, 23] },
//     { f: (b, c, d) => c ^ (b | ~d), s: [6, 10, 15, 21] }
//   ];
//   const k = [
//     // 定义常量数组
//     -680876936, -389564586, 606105819, -1044525330, -176418897, 1200080426, 
//     -1473231341, -45705983, 1770035416, -1958414417, -42063, -1990404162, 
//     1804603682, -40341101, -1502002290, 1236535329, -165796510, -1069501632, 
//     643717713, -373897302, -701558691, 38016083, -660478335, -405537848, 
//     568446438, -1019803690, -187363961, 1163531501, -1444681467, -51403784, 
//     1735328473, -1926607734, -378558, -2022574463, 1839030562, -35309556, 
//     -1530992060, 1272893353, -155497632, -1094730640, 681279174, -358537222, 
//     -722521979, 76029189, -640364487, -421815835, 530742520, -995338651, 
//     -198630844, 1126891415, -1416354905, -57434055, 1700485571, -1894986606, 
//     -1051523, -2054922799, 1873313359, -30611744, -1560198380, 1309151649, 
//     -145523070, -1120210379, 718787259, -343485551
//   ];

//   // 进行四轮处理
//   for (let r = 0; r < 4; r++) {
//     for (let j = 0; j < 16; j++) {
//       // 计算本轮的函数、位移量和常量
//       const f = funcs[r].f(state[1], state[2], state[3]);
//       const s = funcs[r].s[j % 4];
//       const t = k[r * 16 + j];
//       const idx = (j + (r === 1 ? 5 : r === 2 ? 3 : r === 3 ? 7 : 0) * j) % 16;
//       // 更新状态
//       state = [state[3], safe_add(state[1], bit_rol(safe_add(state[0], safe_add(f, safe_add(x[i + idx], t))), s)), state[1], state[2]];
//     }
//   }
//   return state;
// }

// // 安全地添加两个整数，防止溢出
// function safe_add(x, y) {
//   var lsw = (x & 0xFFFF) + (y & 0xFFFF);
//   var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
//   return (msw << 16) | (lsw & 0xFFFF);
// }

// // 将数字向左循环旋转指定的位数
// function bit_rol(num, cnt) {
//   return (num << cnt) | (num >>> (32 - cnt));
// }

// // 将字符串转换为字节数组
// function str2binl(str) {
//   var bin = [];
//   var mask = (1 << chrsz) - 1;
//   for (var i = 0; i < str.length * chrsz; i += chrsz) {
//     bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (i % 32);
//   }
//   return bin;
// }

// // 将字节数组转换为十六进制字符串
// function binl2hex(binarray) {
//   var hex_tab = hexcase ? '0123456789ABCDEF' : '0123456789abcdef';
//   var str = '';
//   for (var i = 0; i < binarray.length * 4; i++) {
//     str += hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF) +
//            hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xF);
//   }
//   return str;
// }