// ============================================================
// 加密模块 v2 - 48密钥体系 / 12层嵌套加密(A→B→C) / AES-256-GCM
// 群组密钥嵌套封装 + 消息AES-GCM加密
// 基于 Web Crypto API, 全部在浏览器端执行, 服务器不接触明文
// ============================================================

const CryptoModule = (() => {

  // ---------- 基础工具 ----------

  function b64encode(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function b64decode(str) {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function concatBytes(arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const result = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      result.set(a, offset);
      offset += a.length;
    }
    return result;
  }

  function randomBytes(length) {
    const arr = new Uint8Array(length);
    crypto.getRandomValues(arr);
    return arr;
  }

  async function importAESKey(rawBytes) {
    return await crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  }

  async function aesEncrypt(keyBytes, iv, plaintext) {
    const key = await importAESKey(keyBytes);
    const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return new Uint8Array(enc);
  }

  async function aesDecrypt(keyBytes, iv, ciphertext) {
    const key = await importAESKey(keyBytes);
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new Uint8Array(dec);
  }

  // ---------- RSA 密钥 ----------

  async function generateRSAKeyPair() {
    return await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']
    );
  }

  async function generate48KeyPairs() {
    const pairs = [];
    for (let i = 0; i < 48; i++) {
      pairs.push(await generateRSAKeyPair());
    }
    return pairs;
  }

  async function exportPublicKey(keyPair) {
    return await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  }

  async function exportPrivateKey(keyPair) {
    return await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  }

  async function importPublicKey(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
  }

  async function importPrivateKey(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
  }

  async function rsaEncrypt(jwk, data) {
    const pubKey = await importPublicKey(jwk);
    const enc = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, data);
    return new Uint8Array(enc);
  }

  async function rsaDecrypt(jwk, data) {
    const privKey = await importPrivateKey(jwk);
    const dec = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, data);
    return new Uint8Array(dec);
  }

  // ---------- 解码顺序 ----------

  function generateDecodeOrder() {
    const indices = Array.from({ length: 48 }, (_, i) => i);
    for (let i = indices.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    return indices.slice(0, 12);
  }

  // ---------- OTP ----------

  function generateOTP() {
    return b64encode(randomBytes(32));
  }

  async function deriveKeyFromOTP(otpBase64, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(otpBase64), 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt || new Uint8Array(16), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
  }

  // ---------- 密钥包 (初始交换) ----------

  async function createKeyBundle(keyPairs, decodeOrder, otp) {
    const privateKeys = {};
    for (const idx of decodeOrder) {
      privateKeys[idx] = await exportPrivateKey(keyPairs[idx]);
    }
    const bundle = { decode_order: decodeOrder, private_keys: privateKeys, created_at: Date.now() };
    const plaintext = new TextEncoder().encode(JSON.stringify(bundle));
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await deriveKeyFromOTP(otp, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return { salt: b64encode(salt), iv: b64encode(iv), ciphertext: b64encode(new Uint8Array(ciphertext)) };
  }

  async function decryptKeyBundle(encrypted, otp) {
    const salt = b64decode(encrypted.salt);
    const iv = b64decode(encrypted.iv);
    const ciphertext = b64decode(encrypted.ciphertext);
    const key = await deriveKeyFromOTP(otp, salt);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  // ============================================================
  // 核心: 12层嵌套群组密钥封装 (A→B→C 洋葱式)
  // ============================================================

  /**
   * 用12层嵌套加密封装群组AES密钥
   * 结构(从内到外):
   *   W12 = AES(L12, K_group)
   *   E12 = RSA(pub12, L12)
   *   W11 = AES(L11, W12 || E12)
   *   E11 = RSA(pub11, L11)
   *   ...
   *   W1  = AES(L1,  W2 || E2)
   *   E1  = RSA(pub1, L1)   ← 唯一外露的RSA封装
   * 解密时必须按顺序使用12个私钥, 每层解封后才能进入下一层
   *
   * @param {Uint8Array} groupKey - 32字节群组AES密钥
   * @param {Array} publicKeys - 48个公钥(JWK数组)
   * @param {Array} decodeOrder - 12个活跃索引(使用顺序)
   * @returns {Object} { wrapped_key, wrap_iv, e_values }
   */
  async function wrapGroupKey(groupKey, publicKeys, decodeOrder) {
    const layerKeys = [];
    const layerIVs = [];
    for (let i = 0; i < 12; i++) {
      layerKeys.push(randomBytes(32));
      layerIVs.push(randomBytes(12));
    }

    // 第12层(最内层): AES加密群组密钥
    let ci = await aesEncrypt(layerKeys[11], layerIVs[11], groupKey);
    // RSA封装第12层AES密钥
    let ei = await rsaEncrypt(publicKeys[decodeOrder[11]], layerKeys[11]);

    // 第11层到第2层: 嵌套封装
    for (let i = 10; i >= 1; i--) {
      const payload = concatBytes([ci, ei]); // 内层密文 || 内层RSA封装的AES密钥
      ci = await aesEncrypt(layerKeys[i], layerIVs[i], payload);
      ei = await rsaEncrypt(publicKeys[decodeOrder[i]], layerKeys[i]);
    }

    // 第1层(最外层): 封装最后一层
    const payload1 = concatBytes([ci, ei]);
    const c1 = await aesEncrypt(layerKeys[0], layerIVs[0], payload1);
    const e1 = await rsaEncrypt(publicKeys[decodeOrder[0]], layerKeys[0]);

    // 组装e_values: 仅decodeOrder[0]位置是真实E1, 其余47个为诱饵
    const eValues = new Array(48).fill(null);
    eValues[decodeOrder[0]] = b64encode(e1);
    for (let i = 0; i < 48; i++) {
      if (eValues[i] === null) {
        eValues[i] = b64encode(randomBytes(256));
      }
    }

    return {
      wrapped_key: b64encode(c1),
      wrap_iv: b64encode(concatBytes(layerIVs)), // 12个IV拼接, 共144字节
      e_values: eValues
    };
  }

  /**
   * 解密12层嵌套封装, 还原群组AES密钥
   * @param {Object} wrap - { wrapped_key, wrap_iv, e_values }
   * @param {Object} privateKeys - { index: JWK私钥 } (12个活跃私钥)
   * @param {Array} decodeOrder - 12个活跃索引
   * @returns {Uint8Array} 群组AES密钥(32字节)
   */
  async function unwrapGroupKey(wrap, privateKeys, decodeOrder) {
    const allIVs = b64decode(wrap.wrap_iv);
    const eValues = wrap.e_values;

    // 第1层: RSA解密得到L1, AES解密得到 W2 || E2
    const e1 = b64decode(eValues[decodeOrder[0]]);
    const l1 = await rsaDecrypt(privateKeys[decodeOrder[0]], e1);
    const iv1 = allIVs.slice(0, 12);
    let payload = await aesDecrypt(l1, iv1, b64decode(wrap.wrapped_key));

    // 第2层到第11层: 逐层剥离
    for (let i = 1; i <= 10; i++) {
      const ei = payload.slice(-256);       // 后256字节是RSA封装的AES密钥
      const ci = payload.slice(0, -256);    // 前面是内层密文
      const li = await rsaDecrypt(privateKeys[decodeOrder[i]], ei);
      const ivi = allIVs.slice(i * 12, (i + 1) * 12);
      payload = await aesDecrypt(li, ivi, ci);
    }

    // 第12层(最内层): 还原群组密钥
    const e12 = payload.slice(-256);
    const c12 = payload.slice(0, -256);
    const l12 = await rsaDecrypt(privateKeys[decodeOrder[11]], e12);
    const iv12 = allIVs.slice(132, 144);
    const groupKey = await aesDecrypt(l12, iv12, c12);

    return groupKey;
  }

  // ---------- 消息加解密 (用群组AES密钥, AES-GCM) ----------

  async function encryptMessage(plaintextObj, groupKey) {
    const plaintext = new TextEncoder().encode(JSON.stringify(plaintextObj));
    const iv = randomBytes(12);
    const key = await importAESKey(groupKey);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return {
      ciphertext: b64encode(new Uint8Array(ciphertext)),
      aes_iv: b64encode(iv)
    };
  }

  async function decryptMessage(msg, groupKey) {
    const iv = b64decode(msg.aes_iv);
    const ciphertext = b64decode(msg.ciphertext);
    const key = await importAESKey(groupKey);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  // 生成新的群组AES密钥
  function generateGroupKey() {
    return randomBytes(32);
  }

  // ---------- 持久化 ----------

  function store(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); return true; }
    catch (e) { return false; }
  }

  function load(key) {
    try {
      const v = localStorage.getItem(key);
      return v ? JSON.parse(v) : null;
    } catch (e) { return null; }
  }

  function remove(key) {
    localStorage.removeItem(key);
  }

  // ---------- OTP 4小时自毁 ----------

  function scheduleOTPDestruction(otpKey) {
    const destroyAt = Date.now() + 4 * 3600 * 1000;
    store('otp_destroy_at', destroyAt);
    const check = () => {
      if (Date.now() >= destroyAt) {
        remove(otpKey);
        remove('otp_destroy_at');
      } else {
        setTimeout(check, Math.min(destroyAt - Date.now(), 60000));
      }
    };
    setTimeout(check, 60000);
  }

  return {
    generate48KeyPairs, generateRSAKeyPair,
    exportPublicKey, exportPrivateKey, importPublicKey, importPrivateKey,
    generateDecodeOrder,
    generateOTP, createKeyBundle, decryptKeyBundle,
    // 核心嵌套加密
    wrapGroupKey, unwrapGroupKey, generateGroupKey,
    // 消息加解密
    encryptMessage, decryptMessage,
    // 工具
    b64encode, b64decode, randomBytes, concatBytes,
    store, load, remove, scheduleOTPDestruction
  };
})();
