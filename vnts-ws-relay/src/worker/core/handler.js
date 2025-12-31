import { NetPacket } from './packet.js';  
import { PROTOCOL, TRANSPORT_PROTOCOL } from './constants.js';  
import { VntContext } from './context.js';  
  
export class PacketHandler {  
  constructor(env) {  
    this.env = env;  
    this.cache = new Map(); // 简化的缓存实现  
  }  
  
  async handle(context, packet, addr, tcpSender) {  
    try {  
      // 检查是否为网关包  
      if (packet.is_gateway()) {  
        return await this.handleServerPacket(context, packet, addr, tcpSender);  
      } else {  
        return await this.handleClientPacket(context, packet, addr);  
      }  
    } catch (error) {  
      console.error('Packet handling error:', error);  
      return null;  
    }  
  }  
  
  async handleServerPacket(context, packet, addr, tcpSender) {  
    // 处理服务协议  
    if (packet.protocol() === PROTOCOL.SERVICE) {  
      switch (packet.transport_protocol()) {  
        case TRANSPORT_PROTOCOL.HandshakeRequest:  
          return this.handleHandshake(packet, addr);  
          
        case TRANSPORT_PROTOCOL.SecretHandshakeRequest:  
          return await this.handleSecretHandshake(context, packet, addr);  
          
        case TRANSPORT_PROTOCOL.RegistrationRequest:  
          return await this.handleRegistration(context, packet, addr, tcpSender);  
          
        default:  
          return null;  
      }  
    }  
      
    // 处理控制协议  
    if (packet.protocol() === PROTOCOL.CONTROL) {  
      switch (packet.transport_protocol()) {  
        case TRANSPORT_PROTOCOL.Ping:  
          return this.handlePing(packet, context);  
          
        case TRANSPORT_PROTOCOL.AddrRequest:  
          return this.handleAddrRequest(addr);  
          
        default:  
          return null;  
      }  
    }  
  
    // 处理数据包转发  
    return await this.handleDataForward(context, packet, addr, tcpSender);  
  }  
  
  async handleClientPacket(context, packet, addr) {  
    // 客户端包处理逻辑 - 主要是转发  
    if (!context.linkContext) {  
      throw new Error('No link context for client packet');  
    }  
      
    return await this.forwardPacket(context.linkContext, packet);  
  }  
  
  handleHandshake(packet, addr) {  
    // 创建握手响应  
    const response = NetPacket.new_encrypt(32);  
    const view = new DataView(response.data.buffer);  
      
    // 设置响应头  
    view.setUint8(0, PROTOCOL.SERVICE);  
    view.setUint8(1, TRANSPORT_PROTOCOL.HandshakeResponse);  
    view.setUint16(2, 0, true); // flags  
    view.setUint8(4, 0); // ttl  
    view.setUint32(5, 0, true); // source (server)  
    view.setUint32(9, packet.source(), true); // destination (client)  
      
    // 设置握手响应数据  
    const payload = response.payload();  
    const payloadView = new DataView(payload.buffer, payload.byteOffset);  
    payloadView.setUint32(0, 0x76774e54, true); // magic  
    payloadView.setUint32(4, 10000001, true); // server peer id  
    payloadView.setUint32(8, 1, true); // version  
      
    return response;  
  }  
  
  async handleSecretHandshake(context, packet, addr) {  
    // 加密握手处理  
    // 这里需要实现 RSA/AES 握手逻辑  
    console.log('Secret handshake request from', addr);  
    return null;  
  }  
  
  async handleRegistration(context, packet, addr, tcpSender) {  
    // 客户端注册处理  
    console.log('Registration request from', addr);  
      
    // 创建注册响应  
    const response = NetPacket.new_encrypt(16);  
    const view = new DataView(response.data.buffer);  
      
    view.setUint8(0, PROTOCOL.SERVICE);  
    view.setUint8(1, TRANSPORT_PROTOCOL.RegistrationResponse);  
    view.setUint32(5, 0, true); // source  
    view.setUint32(9, packet.source(), true); // destination  
      
    return response;  
  }  
  
  handlePing(packet, context) {  
    // 处理 ping 请求，返回 pong  
    const response = NetPacket.new_encrypt(16);  
    const view = new DataView(response.data.buffer);  
      
    view.setUint8(0, PROTOCOL.CONTROL);  
    view.setUint8(1, TRANSPORT_PROTOCOL.Pong);  
    view.setUint32(5, 0, true); // source  
    view.setUint32(9, packet.source(), true); // destination  
      
    // 复制 ping 负载到 pong  
    const payload = response.payload();  
    payload.set(packet.payload().slice(0, 12));  
      
    // 设置 epoch  
    const payloadView = new DataView(payload.buffer, payload.byteOffset);  
    payloadView.setUint16(12, Math.floor(Date.now() / 1000) & 0xFFFF, true);  
      
    return response;  
  }  
  
  handleAddrRequest(addr) {  
    // 返回客户端地址信息  
    const response = NetPacket.new_encrypt(6);  
    const view = new DataView(response.data.buffer);  
      
    view.setUint8(0, PROTOCOL.CONTROL);  
    view.setUint8(1, TRANSPORT_PROTOCOL.AddrResponse);  
    view.setUint32(5, 0, true); // source  
      
    // 设置地址信息  
    const payload = response.payload();  
    const payloadView = new DataView(payload.buffer, payload.byteOffset);  
      
    // 解析 IPv4 地址  
    const ipv4 = addr.ip;  
    if (ipv4 && typeof ipv4 === 'string') {  
      const parts = ipv4.split('.').map(Number);  
      const ipv4Num = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];  
      payloadView.setUint32(0, ipv4Num, true);  
    }  
    payloadView.setUint16(4, addr.port || 0, true);  
      
    return response;  
  }  
  
  async handleDataForward(context, packet, addr, tcpSender) {  
    // 数据包转发逻辑  
    if (packet.incr_ttl() > 1) {  
      // 检查是否禁用中继  
      if (this.env.VNT_DISABLE_RELAY === '1') {  
        console.log('Relay disabled, dropping packet');  
        return null;  
      }  
        
      // 转发到目标地址  
      const destination = packet.destination();  
      if (this.isBroadcast(destination)) {  
        return await this.broadcast(context, packet);  
      } else {  
        return await this.forwardToDestination(context, packet, destination);  
      }  
    }  
    return null;  
  }  
  
  async forwardPacket(linkContext, packet) {  
    // 客户端包转发  
    const destination = packet.destination();  
      
    if (this.isBroadcast(destination)) {  
      return await this.broadcast(linkContext, packet);  
    } else {  
      // 查找目标客户端  
      const clientInfo = linkContext.networkInfo.clients.get(destination);  
      if (clientInfo && clientInfo.online) {  
        // 转发到特定客户端  
        return packet; // 返回原包进行转发  
      }  
    }  
    return null;  
  }  
  
  isBroadcast(addr) {  
    // 检查是否为广播地址  
    return addr === 0xFFFFFFFF || addr === 0;  
  }  
  
  async broadcast(context, packet) {  
    // 广播到所有客户端  
    console.log('Broadcasting packet');  
    return packet;  
  }  
  
  async forwardToDestination(context, packet, destination) {  
    // 转发到特定目标  
    console.log(`Forwarding to ${destination}`);  
    return packet;  
  }  
  
  async leave(context) {  
    // 清理连接  
    await context.leave(this.cache);  
  }  
}
