import { PACKET_HEADER_SIZE, ENCRYPTION_RESERVED } from "./constants.js";  
  
export class NetPacket {  
  constructor(data) {  
    this.data = data;  
    this.offset = 0;  
  }  
  
  static parse(buffer) {  
    // 安全检查：确保输入有效  
    if (!buffer) {  
      throw new Error("Buffer is null or undefined");  
    }  
  
    if (!(buffer instanceof Uint8Array) && !(buffer instanceof ArrayBuffer)) {  
      throw new Error(  
        "Invalid buffer type: expected Uint8Array or ArrayBuffer"  
      );  
    }  
  
    // 获取缓冲区长度  
    const length =  
      buffer instanceof Uint8Array ? buffer.length : buffer.byteLength;  
  
    if (length < 12) {  
      // VNT header is 12 bytes  
      throw new Error(  
        `Packet too short: ${length} bytes, minimum 12 bytes required`  
      );  
    }  
  
    try {  
      const packet = new NetPacket(buffer);  
      packet.parseHeader();  
      return packet;  
    } catch (error) {  
      throw new Error(`Failed to parse VNT packet: ${error.message}`);  
    }  
  }  
  
  // 新增：快速解析头部方法  
  static fastParse(buffer) {  
    if (!buffer || buffer.length < 12) {  
      throw new Error("Packet too short for fast parsing");  
    }  
  
    const packet = new NetPacket(buffer);  
    packet.fastParseHeader();  
    return packet;  
  }  
  
  // 新增：快速头部解析  
  fastParseHeader() {  
    const view = new DataView(this.data.buffer || this.data);  
      
    // 只解析必要的字段用于路由判断  
    this.protocol = view.getUint8(1);  
    this.transportProtocol = view.getUint8(2);  
    this.source = view.getUint32(4, false);  
    this.destination = view.getUint32(8, false);  
    this.offset = 12;  
  }  
  
  parseHeader() {  
    // 安全检查：确保数据存在且类型正确  
    if (!this.data) {  
      throw new Error("Packet data is null or undefined");  
    }  
  
    // 确保有有效的 ArrayBuffer  
    let buffer;  
    if (this.data.buffer) {  
      buffer = this.data.buffer;  
    } else if (this.data instanceof Uint8Array) {  
      // 创建新的 ArrayBuffer 并复制数据  
      buffer = new ArrayBuffer(this.data.length);  
      new Uint8Array(buffer).set(this.data);  
    } else if (this.data instanceof ArrayBuffer) {  
      buffer = this.data;  
    } else {  
      throw new Error(  
        "Invalid data type for packet parsing: expected Uint8Array or ArrayBuffer"  
      );  
    }  
  
    // 安全检查：确保缓冲区足够大以包含协议头  
    if (buffer.byteLength < 12) {  
      throw new Error(  
        "Packet too short: minimum 12 bytes required for VNT header"  
      );  
    }  
  
    const view = new DataView(buffer);  
  
    try {  
      // 正确的 VNT 协议头解析  
      const byte0 = view.getUint8(0);  
      this.version = byte0 & 0x0f; // 低4位是版本  
      this.flags = (byte0 & 0xf0) >> 4; // 高4位是标志  
      this.protocol = view.getUint8(1); // 协议类型  
      this.transportProtocol = view.getUint8(2); // 传输协议  
      this.ttl = view.getUint8(3); // TTL  
  
      // IP地址使用大端序  
      const sourceIpBytes = [  
        view.getUint8(4),  
        view.getUint8(5),  
        view.getUint8(6),  
        view.getUint8(7),  
      ];  
      this.source = new DataView(  
        new Uint8Array(sourceIpBytes).buffer  
      ).getUint32(0, false); // 大端序  
  
      const destIpBytes = [  
        view.getUint8(8),  
        view.getUint8(9),  
        view.getUint8(10),  
        view.getUint8(11),  
      ];  
      this.destination = new DataView(  
        new Uint8Array(destIpBytes).buffer  
      ).getUint32(0, false); // 大端序  
  
      this.offset = 12; // VNT header size  
    } catch (error) {  
      throw new Error(`Failed to parse VNT packet header: ${error.message}`);  
    }  
  }  
  
  protocol() {  
    return this.protocol;  
  }  
  
  transport_protocol() {  
    return this.transportProtocol;  
  }  
  
  source() {  
    return this.source;  
  }  
  
  destination() {  
    return this.destination;  
  }  
  
  payload() {  
    return this.data.slice(this.offset);  
  }  
  
  payload_mut() {  
    return new Uint8Array(  
      this.data.buffer,  
      this.offset,  
      this.data.length - this.offset  
    );  
  }  
  
  is_encrypt() {  
    return (this.flags & 0x01) !== 0;  
  }  
  
  is_gateway() {  
    return (this.flags & 0x04) !== 0;  
  }  
  
  incr_ttl() {  
    // 安全检查：确保数据存在  
    if (!this.data) {  
      throw new Error("Cannot increment TTL: packet data is null");  
    }  
  
    // 确保 TTL 值有效  
    if (typeof this.ttl !== "number" || this.ttl < 0) {  
      throw new Error("Invalid TTL value");  
    }  
  
    // 增加 TTL  
    this.ttl++;  
  
    // 确保有有效的 ArrayBuffer  
    let buffer;  
    if (this.data.buffer) {  
      buffer = this.data.buffer;  
    } else if (this.data instanceof Uint8Array) {  
      buffer = new ArrayBuffer(this.data.length);  
      new Uint8Array(buffer).set(this.data);  
    } else if (this.data instanceof ArrayBuffer) {  
      buffer = this.data;  
    } else {  
      throw new Error("Invalid data type for packet modification");  
    }  
  
    // 安全检查：确保缓冲区足够大  
    if (buffer.byteLength < 4) {  
      throw new Error("Packet too short to modify TTL");  
    }  
  
    try {  
      const view = new DataView(buffer);  
      view.setUint8(3, this.ttl); // TTL 在字节3  
      return this.ttl;  
    } catch (error) {  
      throw new Error(`Failed to increment TTL: ${error.message}`);  
    }  
  }  
  
  buffer() {  
    return this.data;  
  }  
  
  static new(size) {  
    const totalSize = 12 + size; // VNT header is 12 bytes  
    const buffer = new Uint8Array(totalSize);  
    // 确保第一个字节不包含加密标志  
    buffer[0] = 0x00; // 清除所有标志  
    return new NetPacket(buffer);  
  }  
  
  static new_encrypt(size) {  
    const totalSize = 12 + size + ENCRYPTION_RESERVED; // VNT header is 12 bytes  
    const buffer = new Uint8Array(totalSize);  
    return new NetPacket(buffer);  
  }  
  
  // 安全获取 ArrayBuffer 的辅助方法  
  _getArrayBuffer() {  
    if (!this.data) {  
      throw new Error("Packet data is null");  
    }  
  
    if (this.data.buffer) {  
      return this.data.buffer;  
    } else if (this.data instanceof Uint8Array) {  
      const buffer = new ArrayBuffer(this.data.length);  
      new Uint8Array(buffer).set(this.data);  
      return buffer;  
    } else if (this.data instanceof ArrayBuffer) {  
      return this.data;  
    } else {  
      throw new Error("Invalid data type");  
    }  
  }  
  
  // 验证数据包完整性  
  validate() {  
    if (!this.data) {  
      throw new Error("Packet data is null");  
    }  
  
    if (typeof this.protocol !== "number") {  
      throw new Error("Invalid protocol field");  
    }  
  
    if (typeof this.transportProtocol !== "number") {  
      throw new Error("Invalid transport protocol field");  
    }  
  
    if (typeof this.source !== "number" || this.source < 0) {  
      throw new Error("Invalid source address");  
    }  
  
    if (typeof this.destination !== "number" || this.destination < 0) {  
      throw new Error("Invalid destination address");  
    }  
  
    return true;  
  }  
  
  // 设置方法 - 移到类内部  
  set_protocol(protocol) {  
    const buffer = this._getArrayBuffer();  
    const view = new DataView(buffer);  
    view.setUint8(1, protocol);  
    this.protocol = protocol;  
  }  
  
  set_transport_protocol(transportProtocol) {  
    const buffer = this._getArrayBuffer();  
    const view = new DataView(buffer);  
    view.setUint8(2, transportProtocol);  
    this.transportProtocol = transportProtocol;  
  }  
  
  set_source(source) {  
    const buffer = this._getArrayBuffer();  
    const view = new DataView(buffer);  
    // 大端序存储IP  
    view.setUint8(4, (source >> 24) & 0xff);  
    view.setUint8(5, (source >> 16) & 0xff);  
    view.setUint8(6, (source >> 8) & 0xff);  
    view.setUint8(7, source & 0xff);  
    this.source = source;  
  }  
  
  set_destination(destination) {  
    const buffer = this._getArrayBuffer();  
    const view = new DataView(buffer);  
  
    // 关键修复：使用正确的字节顺序和偏移  
    // VNT 协议中地址存储在字节 8-11  
    const destBytes = this.intToIpv4Bytes(destination);  
  
    console.log(`[DEBUG] Setting destination bytes: [${destBytes.join(", ")}]`);  
  
    // 按字节设置，确保与 Rust 一致  
    view.setUint8(8, destBytes[0]);  
    view.setUint8(9, destBytes[1]);  
    view.setUint8(10, destBytes[2]);  
    view.setUint8(11, destBytes[3]);  
  
    this.destination = destination;  
  
    // 验证完整的包头  
    const header = [];  
    for (let i = 0; i < 12; i++) {  
      header.push(view.getUint8(i));  
    }  
    console.log(`[DEBUG] Complete header: [${header.join(", ")}]`);  
  }  
  
  set_source(source) {  
    const buffer = this._getArrayBuffer();  
    const view = new DataView(buffer);  
  
    // 源地址存储在字节 4-7  
    const sourceBytes = this.intToIpv4Bytes(source);  
  
    console.log(`[DEBUG] Setting source bytes: [${sourceBytes.join(", ")}]`);  
  
    view.setUint8(4, sourceBytes[0]);  
    view.setUint8(5, sourceBytes[1]);  
    view.setUint8(6, sourceBytes[2]);  
    view.setUint8(7, sourceBytes[3]);  
  
    this.source = source;  
  }  
  
  set_payload(payload) {  
    const dataStart = 12; // VNT header size  
    if (this.data.length < dataStart + payload.length) {  
      throw new Error("Insufficient space for payload");  
    }  
  
    // 复制 payload 数据  
    const dataArray =  
      this.data instanceof Uint8Array ? this.data : new Uint8Array(this.data);  
    dataArray.set(payload, dataStart);  
    this.data = dataArray;  
  }  
  
  set_gateway_flag(isGateway) {  
    const buffer = this._getArrayBuffer();  
    const view = new DataView(buffer);  
    const byte0 = view.getUint8(0);  
  
    if (isGateway) {  
      view.setUint8(0, byte0 | 0x40); // 设置第6位  
    } else {  
      view.setUint8(0, byte0 & ~0x40); // 清除第6位  
    }  
  
    // 更新内部flags状态  
    this.flags = (view.getUint8(0) & 0xf0) >> 4;  
  }  
  
  intToIpv4Bytes(ipInt) {  
    return [  
      (ipInt >> 24) & 0xff,  
      (ipInt >> 16) & 0xff,  
      (ipInt >> 8) & 0xff,  
      ipInt & 0xff,  
    ];  
  }  
  
  set_default_version() {  
    const buffer = this._getArrayBuffer();  
    const view = new DataView(buffer);  
    const byte0 = view.getUint8(0);  
    // V2 = 2, 保留高4位标志，设置低4位为版本号  
    view.setUint8(0, (byte0 & 0xf0) | 0x02);  
    this.version = 2;  
  }  
  
  first_set_ttl(ttl) {  
    console.log(`[调试] first_set_ttl 被调用，ttl=${ttl}`);  
  
    const buffer = this._getArrayBuffer();  
    const view = new DataView(buffer);  
  
    // 记录修改前的值  
    const oldValue = view.getUint8(3);  
    console.log(  
      `[调试] TTL字节修改前: 0x${oldValue.toString(16).padStart(2, "0")}`  
    );  
  
    // 设置 TTL  
    const newValue = (ttl << 4) | ttl;  
    view.setUint8(3, newValue);  
  
    // 记录修改后的值  
    console.log(  
      `[调试] TTL字节修改后: 0x${newValue.toString(16).padStart(2, "0")}`  
    );  
  
    this.ttl = ttl;  
  }  
}
