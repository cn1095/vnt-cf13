import { ENCRYPTION_RESERVED } from './constants.js';  
  
/**  
 * RSA 加密器  
 * 基于 vnt_s/vnts/src/cipher/rsa_cipher.rs 实现  
 */  
export class RsaCipher {  
  constructor(privateKeyDer, publicKeyDer) {  
    this.privateKeyDer = privateKeyKeyDer;  
    this.publicKeyDer = publicKeyDer;  
    this.finger = this.calculateFinger(publicKeyDer);  
  }  
  
  /**  
   * 计算公钥指纹  
   */  
  calculateFinger(publicKeyDer) {  
    // 使用 SHA256 计算指纹并返回 base64  
    const hashBuffer = crypto.subtle.digest('SHA-256', publicKeyDer);  
    return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));  
  }  
  
  /**  
   * 获取指纹  
   */  
  finger() {  
    return this.finger;  
  }  
  
  /**  
   * 获取公钥  
   */  
  publicKey() {  
    return this.publicKeyDer;  
  }  
  
  /**  
   * RSA 解密  
   * 基于 vnt_s/vnts/src/cipher/rsa_cipher.rs:116-148 实现  
   */  
  async decrypt(netPacket) {  
    try {  
      // 导入私钥  
      const privateKey = await crypto.subtle.importKey(  
        'pkcs8',  
        this.privateKeyDer,  
        { name: 'RSA-OAEP', hash: 'SHA-256' },  
        false,  
        ['decrypt']  
      );  
  
      // 解密数据  
      const decryptedData = await crypto.subtle.decrypt(  
        { name: 'RSA-OAEP' },  
        privateKey,  
        netPacket.payload()  
      );  
  
      // 创建 RSA 密钥体  
      const secretBody = new RsaSecretBody(new Uint8Array(decryptedData));  
        
      // 构建 nonce  
      const nonceRaw = this.buildNonceRaw(netPacket);  
        
      // 验证指纹  
      const hasher = await crypto.subtle.digest('SHA-256',   
        new Uint8Array([...secretBody.body(), ...nonceRaw])  
      );  
      const hashArray = new Uint8Array(hasher);  
      const expectedFinger = hashArray.slice(16);  
        
      if (!this.arraysEqual(expectedFinger, secretBody.finger())) {  
        throw new Error('finger err');  
      }  
  
      return secretBody;  
    } catch (error) {  
      throw new Error(`decrypt failed ${error.message}`);  
    }  
  }  
  
  /**  
   * RSA 加密  
   * 基于 vnt_s/vnt/vnt/src/cipher/rsa_cipher.rs:69-111 实现  
   */  
  async encrypt(netPacket) {  
    if (netPacket.reserve() < 256) { // RSA_ENCRYPTION_RESERVED  
      throw new Error('too short');  
    }  
  
    const dataLen = netPacket.data_len() + 256;  
    netPacket.set_data_len(dataLen);  
  
    const nonceRaw = this.buildNonceRaw(netPacket);  
    const secretBody = new RsaSecretBody(netPacket.payload_mut());  
      
    // 设置随机数  
    const random = new Uint8Array(64);  
    crypto.getRandomValues(random);  
    secretBody.set_random(random);  
  
    // 计算指纹  
    const hasher = await crypto.subtle.digest('SHA-256',  
      new Uint8Array([...secretBody.body(), ...nonceRaw])  
    );  
    const hashArray = new Uint8Array(hasher);  
    secretBody.set_finger(hashArray.slice(16));  
  
    // 导入公钥并加密  
    const publicKey = await crypto.subtle.importKey(  
      'spki',  
      this.publicKeyDer,  
      { name: 'RSA-OAEP', hash: 'SHA-256' },  
      false,  
      ['encrypt']  
    );  
  
    const encryptedData = await crypto.subtle.encrypt(  
      { name: 'RSA-OAEP' },  
      publicKey,  
      secretBody.buffer()  
    );  
  
    // 创建新的数据包  
    const newPacket = NetPacket.new(new Uint8Array(12 + encryptedData.byteLength));  
    newPacket.buffer_mut().set(netPacket.buffer().slice(0, 12), 0);  
    newPacket.set_payload(new Uint8Array(encryptedData));  
  
    return newPacket;  
  }  
  
  buildNonceRaw(netPacket) {  
    const nonceRaw = new Uint8Array(12);  
    const sourceOctets = this.ipv4ToOctets(netPacket.source());  
    const destOctets = this.ipv4ToOctets(netPacket.destination());  
      
    nonceRaw.set(sourceOctets, 0);  
    nonceRaw.set(destOctets, 4);  
    nonceRaw[8] = netPacket.protocol();  
    nonceRaw[9] = netPacket.transport_protocol();  
    nonceRaw[10] = netPacket.is_gateway() ? 1 : 0;  
    nonceRaw[11] = netPacket.source_ttl();  
      
    return nonceRaw;  
  }  
  
  ipv4ToOctets(ip) {  
    return [  
      (ip >>> 24) & 0xFF,  
      (ip >>> 16) & 0xFF,  
      (ip >>> 8) & 0xFF,  
      ip & 0xFF  
    ];  
  }  
  
  arraysEqual(a, b) {  
    return a.length === b.length && a.every((val, i) => val === b[i]);  
  }  
}  
  
/**  
 * AES-GCM 加密器  
 * 基于 vnt_s/vnt/vnt/src/cipher/aes_gcm/aes_gcm_cipher.rs 实现  
 */  
export class AesGcmCipher {  
  constructor(key, finger) {  
    this.key = key;  
    this.finger = finger;  
  }  
  
  /**  
   * 创建 128 位 AES-GCM 加密器  
   */  
  static new_128(key, finger) {  
    if (key.length !== 16) {  
      throw new Error('Key must be 16 bytes for AES-128');  
    }  
    return new AesGcmCipher(key, finger);  
  }  
  
  /**  
   * 创建 256 位 AES-GCM 加密器  
   */  
  static new_256(key, finger) {  
    if (key.length !== 32) {  
      throw new Error('Key must be 32 bytes for AES-256');  
    }  
    return new AesGcmCipher(key, finger);  
  }  
  
  /**  
   * IPv4 数据包解密  
   * 基于 vnt_s/vnt/vnt/src/cipher/aes_gcm/aes_gcm_cipher.rs:38-76 实现  
   */  
  async decrypt_ipv4(netPacket) {  
    if (!netPacket.is_encrypt()) {  
      throw new Error('not encrypt');  
    }  
  
    if (netPacket.payload().len < 16) { // AES_GCM_ENCRYPTION_RESERVED  
      throw new Error('data err');  
    }  
  
    const nonceRaw = netPacket.head_tag();  
    const secretBody = new SecretBody(netPacket.payload_mut(), this.finger !== null);  
  
    // 验证指纹  
    if (this.finger) {  
      const finger = this.finger.calculate_finger(nonceRaw, secretBody.en_body());  
      if (!this.arraysEqual(finger, secretBody.finger())) {  
        throw new Error('finger err');  
      }  
    }  
  
    try {  
      // 导入 AES 密钥  
      const aesKey = await crypto.subtle.importKey(  
        'raw',  
        this.key,  
        { name: 'AES-GCM' },  
        false,  
        ['decrypt']  
      );  
  
      // 解密数据  
      const decryptedData = await crypto.subtle.decrypt(  
        {  
          name: 'AES-GCM',  
          iv: nonceRaw,  
        },  
        aesKey,  
        secretBody.en_body()  
      );  
  
      // 更新数据包  
      netPacket.set_encrypt_flag(false);  
      netPacket.set_data_len(netPacket.data_len() - 16);  
      netPacket.payload_mut().set(new Uint8Array(decryptedData), 0);  
  
    } catch (error) {  
      throw new Error(`解密失败: ${error.message}`);  
    }  
  }  
  
  /**  
   * IPv4 数据包加密  
   * 基于 vnt_s/vnt/vnt/src/cipher/aes_gcm/aes_gcm_cipher.rs:79-112 实现  
   */  
  async encrypt_ipv4(netPacket) {  
    if (netPacket.reserve() < 16) { // AES_GCM_ENCRYPTION_RESERVED  
      throw new Error('too short');  
    }  
  
    const nonceRaw = netPacket.head_tag();  
    const dataLen = netPacket.data_len() + 16;  
    netPacket.set_data_len(dataLen);  
  
    const secretBody = new SecretBody(netPacket.payload_mut(), this.finger !== null);  
    secretBody.set_random(Math.floor(Math.random() * 0xFFFFFFFF));  
  
    try {  
      // 导入 AES 密钥  
      const aesKey = await crypto.subtle.importKey(  
        'raw',  
        this.key,  
        { name: 'AES-GCM' },  
        false,  
        ['encrypt']  
      );  
  
      // 加密数据  
      const encryptedData = await crypto.subtle.encrypt(  
        {  
          name: 'AES-GCM',  
          iv: nonceRaw,  
        },  
        aesKey,  
        secretBody.body()  
      );  
  
      const encryptedArray = new Uint8Array(encryptedData);  
      const tag = encryptedArray.slice(-16); // GCM tag 是最后 16 字节  
      const ciphertext = encryptedArray.slice(0, -16);  
  
      // 设置加密结果  
      secretBody.set_body(ciphertext);  
      secretBody.set_tag(tag);  
  
      if (this.finger) {  
        const finger = this.finger.calculate_finger(nonceRaw, secretBody.en_body());  
        secretBody.set_finger(finger);  
      }  
  
      netPacket.set_encrypt_flag(true);  
  
    } catch (error) {  
      throw new Error(`加密失败: ${error.message}`);  
    }  
  }  
  
  arraysEqual(a, b) {  
    return a.length === b.length && a.every((val, i) => val === b[i]);  
  }  
}  
  
/**  
 * 指纹计算器  
 * 基于 vnt_s/vnts/src/cipher/finger.rs 实现  
 */  
export class Finger {  
  constructor(token) {  
    this.token = token;  
  }  
  
  /**  
   * 计算指纹  
   */  
  calculate_finger(nonceRaw, data) {  
    const combined = new Uint8Array([...nonceRaw, ...data, ...new TextEncoder().encode(this.token)]);  
    return crypto.subtle.digest('SHA-256', combined).then(hash => {  
      return new Uint8Array(hash).slice(0, 16); // 取前 16 字节作为指纹  
    });  
  }  
}  
  
/**  
 * RSA 密钥体  
 * 基于 vnt_s/vnts/src/protocol/body.rs:529-563 实现  
 */  
export class RsaSecretBody {  
  constructor(buffer) {  
    this.buffer = buffer;  
    this.len = buffer.length;  
  }  
  
  data() {  
    return this.buffer.slice(0, this.len - 64); // 减去 random(32) + finger(32)  
  }  
  
  random() {  
    return this.buffer.slice(this.len - 64, this.len - 32);  
  }  
  
  body() {  
    return this.buffer.slice(0, this.len - 32);  
  }  
  
  finger() {  
    return this.buffer.slice(this.len - 32);  
  }  
  
  buffer() {  
    return this.buffer;  
  }  
  
  set_random(random) {  
    this.buffer.set(random, this.len - 64);  
  }  
  
  set_finger(finger) {  
    this.buffer.set(finger, this.len - 32);  
  }  
}  
  
/**  
 * AES 密钥体  
 * 基于 VNT 协议的 SecretBody 实现  
 */  
export class SecretBody {  
  constructor(buffer, hasFinger) {  
    this.buffer = buffer;  
    this.hasFinger = hasFinger;  
  }  
  
  en_body() {  
    if (this.hasFinger) {  
      return this.buffer.slice(0, this.buffer.length - 16); // 减去 finger  
    }  
    return this.buffer;  
  }  
  
  body() {  
    if (this.hasFinger) {  
      return this.buffer.slice(0, this.buffer.length - 32); // 减去 random + finger  
    }  
    return this.buffer.slice(0, this.buffer.length - 16); // 减去 random  
  }  
  
  body_mut() {  
    return this.buffer;  
  }  
  
  finger() {  
    if (this.hasFinger) {  
      return this.buffer.slice(-16);  
    }  
    return new Uint8Array(0);  
  }  
  
  set_random(random) {  
    const view = new DataView(this.buffer.buffer, this.buffer.byteOffset);  
    view.setUint32(0, random, true);  
  }  
  
  set_tag(tag) {  
    this.buffer.set(tag, this.buffer.length - 16 - (this.hasFinger ? 16 : 0));  
  }  
  
  set_finger(finger) {  
    if (this.hasFinger) {  
      this.buffer.set(finger, this.buffer.length - 16);  
    }  
  }  
}  
  
/**  
 * 生成随机 U64 字符串  
 */  
export function randomU64String() {  
  const array = new Uint8Array(8);  
  crypto.getRandomValues(array);  
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');  
}  
  
/**  
 * 生成 RSA 密钥对  
 */  
export async function generateRsaKeyPair() {  
  const keyPair = await crypto.subtle.generateKey(  
    {  
      name: 'RSA-OAEP',  
      modulusLength: 2048,  
      publicExponent: new Uint8Array([1, 0, 1]),  
      hash: 'SHA-256',  
    },  
    true,  
    ['encrypt', 'decrypt']  
  );  
  
  const privateKeyDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);  
  const publicKeyDer = await crypto.subtle.exportKey('spki', keyPair.publicKey);  
  
  return {  
    privateKey: new Uint8Array(privateKeyDer),  
    publicKey: new Uint8Array(publicKeyDer)  
  };  
}
