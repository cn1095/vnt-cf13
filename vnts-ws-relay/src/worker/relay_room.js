import { NetPacket } from './core/packet.js';    
import { VntContext } from './core/context.js';    
import { PacketHandler } from './core/handler.js';    
import { PROTOCOL, TRANSPORT_PROTOCOL } from './core/constants.js';    
  
export class RelayRoom {    
  constructor(state, env) {    
    this.state = state;    
    this.env = env;    
    this.connections = new Map();    
    this.contexts = new Map();    
    this.packetHandler = new PacketHandler(env); 
    this.clientMap = new Map();   
        
    // 心跳管理    
    this.heartbeatTimers = new Map();    
    this.heartbeatInterval = parseInt(env.HEARTBEAT_INTERVAL || '60') * 1000;    
      
    // 连接信息存储  
    this.connectionInfos = new Map();  
  }    
  
  async fetch(request) {    
    const url = new URL(request.url);    
        
    if (url.pathname === '/ws') {    
      return this.handleWebSocket(request);    
    }    
        
    return new Response('Not Found', { status: 404 });    
  }    
  
  async handleWebSocket(request) {    
    const [client, server] = Object.values(new WebSocketPair());    
    server.accept();    
        
    const clientId = this.generateClientId();    
    const addr = this.parseClientAddress(request);    
        
    console.log(`[DEBUG] New WebSocket connection: ${clientId} from ${JSON.stringify(addr)}`);    
        
    // 创建 VNT 上下文    
    const context = new VntContext({    
      linkAddress: addr,    
      serverCipher: null    
    });    
        
    this.contexts.set(clientId, context);    
    this.connections.set(clientId, server);    
        
    // 初始化连接状态    
    this.initializeConnection(clientId, server);    
        
    // 设置 WebSocket 消息处理    
    server.addEventListener('message', async (event) => {    
      await this.handleMessage(clientId, event.data);    
    });    
        
    server.addEventListener('close', (event) => {    
      console.log(`[调试] WebSocket关闭: ${clientId}`);    
      this.handleClose(clientId);    
    });    
        
    server.addEventListener('error', (error) => {    
      console.error(`[调试] WebSocket错误 ${clientId}:`, error);    
      this.handleClose(clientId);    
    });    
        
    // ping/pong 事件监听    
    server.addEventListener('ping', () => {    
      server.pong();    
    });    
        
    server.addEventListener('pong', () => {    
      this.updateLastActivity(clientId);    
    });    
        
    return new Response(null, {    
      status: 101,    
      webSocket: client    
    });    
  }    
  
  // 初始化连接管理    
  initializeConnection(clientId, server) {    
    console.log(`[调试] 初始化连接: ${clientId}`);    
    const connectionInfo = {    
      server: server,    
      lastActivity: Date.now(),    
      clientId: clientId,    
      isAlive: true    
    };    
        
    this.connectionInfos.set(clientId, connectionInfo);  
        
    // 启动心跳定时器    
    this.startHeartbeat(clientId);    
     this.updateClientMap(); 
    // 启动定期健康检查    
    if (!this.healthCheckInterval) {    
      this.healthCheckInterval = setInterval(() => {    
        this.checkConnectionHealth();    
      }, 300000); // 5分钟    
    }  
  }    
  updateClientMap() {  
    this.clientMap.clear();  
    for (const [clientId, context] of this.contexts) {  
        if (context.virtual_ip) {  
            this.clientMap.set(context.virtual_ip, clientId);  
        }  
    }  
}
  // 启动心跳机制    
  startHeartbeat(clientId) {    
    const server = this.connections.get(clientId);    
    if (!server) return;    
        
    const heartbeatId = setInterval(() => {    
      try {    
        // 只检查WebSocket状态，不检查超时  
        if (server.readyState !== WebSocket.OPEN) {    
          console.log(`[调试] 连接已断开，清理: ${clientId}`);    
          this.handleClose(clientId);    
          return;    
        }    
      } catch (error) {    
        console.error(`[调试] 心跳检查失败 ${clientId}:`, error);    
        this.handleClose(clientId);    
      }    
    }, this.heartbeatInterval);    
        
    this.heartbeatTimers.set(clientId, heartbeatId);    
  }    
  
  // 更新最后活动时间    
  updateLastActivity(clientId) {    
    const connectionInfo = this.getConnectionInfo(clientId);    
    if (connectionInfo) {    
      connectionInfo.lastActivity = Date.now();    
    }    
  }    
  
  // 获取连接信息    
  getConnectionInfo(clientId) {    
    if (!this.connectionInfos) {  
      return null;  
    }  
    return this.connectionInfos.get(clientId);    
  }    
  
  // 轻量级 VNT 头部解析（类似 easytier）  
  parseVNTHeader(buffer) {  
    if (!buffer || buffer.length < 12) return null;  
      
    // 使用 DataView 提升性能  
    const view = new DataView(buffer.buffer || buffer);  
      
    return {  
        source: view.getUint32(4, false),  // 大端序  
        destination: view.getUint32(8, false),  
        protocol: view.getUint8(1),  
        transportProtocol: view.getUint8(2)  
    };  
}  
  
  // 判断是否可以使用快速转发  
  shouldFastForward(data) {  
    if (!data || data.length < 12) return false;  
      
    const protocol = data[1];  
    const transport = data[2];  
      
    // 扩大快速路径范围  
    return (  
        // IPTURN 数据包（最常见）  
        (protocol === 4 && transport === 4) ||  
        // WGIpv4 数据包  
        (protocol === 4 && transport === 2) ||  
        // Ipv4Broadcast 数据包  
        (protocol === 4 && transport === 3) ||  
        // 部分 CONTROL 协议包（ping/pong）  
        (protocol === 3 && (transport === 1 || transport === 2))  
    );  
} 
  
  // 快速转发（零复制）  
  async fastForward(senderId, fullMessage, header) {  
    // 直接使用预计算映射  
    const targetClientId = this.clientMap.get(header.destination);  
      
    if (targetClientId && targetClientId !== senderId) {  
        const targetServer = this.connections.get(targetClientId);  
        if (targetServer && targetServer.readyState === WebSocket.OPEN) {  
            // 零拷贝发送  
            targetServer.send(fullMessage);  
        }  
    }  
}  
  
  async handleMessage(clientId, data) {    
    try {    
      console.log(`[调试] 收到来自 ${clientId} 的数据`);  
        
      if (!data) return;  
          
      // 更新活动时间    
      this.updateLastActivity(clientId);    
          
      // 转换为 Uint8Array    
      let uint8Data;    
      if (data instanceof ArrayBuffer) {    
        uint8Data = new Uint8Array(data);    
      } else if (data instanceof Uint8Array) {    
        uint8Data = data;    
      } else if (ArrayBuffer.isView(data)) {    
        uint8Data = new Uint8Array(data.buffer);    
      } else {    
        console.log(`[调试] 不支持的数据类型: ${typeof data}`);    
        return;    
      }    
  
      // 快速路径：轻量级头部解析  
      const header = this.parseVNTHeader(uint8Data);  
        
      if (this.shouldFastForward(header)) {  
        // 快速转发，跳过复杂解析  
        return await this.fastForward(clientId, uint8Data, header);  
      }  
          
      // 慢速路径：完整 VNT 协议处理（保持兼容性）  
      const context = this.contexts.get(clientId);    
      const server = this.connections.get(clientId);    
          
      if (!context || !server) {    
        console.log(`[DEBUG] No context or server found for ${clientId}`);    
        return;    
      }    
          
      console.log(`[DEBUG] Parsing VNT packet...`);    
      const packet = NetPacket.parse(uint8Data);    
          
      if (!packet || typeof packet !== 'object') {    
        console.log(`[DEBUG] Invalid packet returned from parse`);    
        return;    
      }    
          
      const response = await this.packetHandler.handle(    
        context,    
        packet,    
        context.linkAddress,    
        {    
          send: async (data) => {    
            try {    
              server.send(data);    
            } catch (error) {    
              console.error(`[DEBUG] Failed to send response to ${clientId}:`, error);    
              throw error;    
            }    
          }    
        }    
      );    
          
      // 发送响应    
      if (response) {    
        try {    
          server.send(response.buffer());    
        } catch (error) {    
          console.error(`[调试] 发送响应失败 ${clientId}:`, error);    
          if (error.message.includes('closed') || error.message.includes('terminated')) {    
            this.handleClose(clientId);    
          }    
        }    
      } else {    
        console.log(`[DEBUG] No response generated for ${clientId}`);    
      }    
          
      // 广播到其他连接（如果需要）    
      if (this.shouldBroadcast(packet)) {    
        await this.broadcastPacket(clientId, packet);    
      }    
          
    } catch (error) {    
      console.error(`[调试] 处理 ${clientId} 消息时出错:`, error);    
        
      // 只对严重错误关闭连接    
      if (error.message.includes('WebSocket') || error.message.includes('connection')) {    
        this.handleClose(clientId);    
      }   
    }    
  }    
  
  // 判断是否需要广播    
  shouldBroadcast(packet) {    
    // SERVICE 协议包不应该广播    
    if (packet.protocol === PROTOCOL.SERVICE) {    
      return false;    
    }    
      
    // CONTROL 协议的握手包也不应该广播    
    if (packet.protocol === PROTOCOL.CONTROL &&     
        packet.transportProtocol === TRANSPORT_PROTOCOL.HandshakeRequest) {    
      return false;    
    }    
      
    // ERROR 协议包不需要广播    
    if (packet.protocol === PROTOCOL.ERROR) {    
      return false;    
    }    
      
    return true;    
  }    
  
  async broadcastPacket(senderId, packet) {    
    const senderContext = this.contexts.get(senderId);    
        
    for (const [clientId, server] of this.connections) {    
      if (clientId === senderId) continue;    
          
      try {    
        // 根据路由规则决定是否转发    
        if (this.shouldForward(senderContext, packet)) {    
          console.log(`[DEBUG] Broadcasting packet from ${senderId} to ${clientId}`);    
              
          // 创建新的数据包副本避免引用问题    
          const packetCopy = this.copyPacket(packet);    
          server.send(packetCopy.buffer());    
        }    
      } catch (error) {    
        console.error(`[DEBUG] Broadcast error to ${clientId}:`, error);    
      }    
    }    
  }    
  
  // 复制数据包避免引用问题    
  copyPacket(originalPacket) {    
    try {    
      const buffer = originalPacket.buffer();    
      const copiedBuffer = new Uint8Array(buffer.length);    
      copiedBuffer.set(buffer);    
      return NetPacket.parse(copiedBuffer);    
    } catch (error) {    
      console.error(`[DEBUG] Failed to copy packet:`, error);    
      return originalPacket;    
    }    
  }    
  
  shouldForward(context, packet) {    
    // 实现路由逻辑    
    return packet.protocol !== PROTOCOL.SERVICE;    
  }    
  
  // 连接关闭处理    
  handleClose(clientId) {    
    console.log(`[调试] 开始清理连接: ${clientId}`);    
        
    const context = this.contexts.get(clientId);    
        
    if (context) {    
      try {    
        console.log(`[调试] 清理 ${clientId} 的上下文`);    
        this.packetHandler.leave(context);    
      } catch (error) {    
        console.error(`[调试] 清理 ${clientId} 上下文时出错:`, error);      
      }    
    }    
        
    // 清理心跳定时器    
    const heartbeatId = this.heartbeatTimers.get(clientId);    
    if (heartbeatId) {    
      console.log(`[调试] 停止 ${clientId} 的心跳定时器`);    
      clearInterval(heartbeatId);    
      this.heartbeatTimers.delete(clientId);    
    }    
        
    // 清理连接和上下文    
    this.contexts.delete(clientId);    
    this.connections.delete(clientId);    
      
    // 清理连接信息  
    if (this.connectionInfos) {  
      this.connectionInfos.delete(clientId);  
    }  
      
    // 如果没有活跃连接了，停止健康检查    
    if (this.connections.size === 0 && this.healthCheckInterval) {    
      clearInterval(this.healthCheckInterval);    
      this.healthCheckInterval = null;    
      console.log(`[调试] 停止健康检查定时器`);    
    }  
        
    console.log(`[调试] 连接 ${clientId} 清理完成`);    
  }    
  
  generateClientId() {    
    return Math.random().toString(36).substr(2, 9);    
  }    
  
  parseClientAddress(request) {    
    const cf = request.cf;    
    return {    
      ip: cf?.colo || 'unknown',    
      port: 0    
    };    
  }    
  
  // 定期检查连接状态    
  checkConnectionHealth() {    
    console.log(`[调试] 开始健康检查，当前连接数: ${this.connections.size}`);    
      
    for (const [clientId, server] of this.connections) {    
      // 只检查WebSocket状态，不检查超时  
      if (server.readyState !== WebSocket.OPEN) {  
        console.log(`[调试] 连接 ${clientId} 已断开，准备清理`);    
        this.handleClose(clientId);    
      }  
    }    
      
    console.log(`[调试] 健康检查完成`);    
  }  
}
