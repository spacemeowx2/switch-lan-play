import { createSocket, Socket, AddressInfo } from 'dgram'
import { AuthProvider } from './auth'
const Timeout = 30 * 1000
const IPV4_OFF_SRC = 12
const IPV4_OFF_DST = 16
const OutputEncrypt = false

enum ForwarderType {
  Keepalive = 0,
  Ipv4 = 1,
  Ping = 2,
  Ipv4Frag = 3,
}

interface CacheItem {
  expireAt: number
  rinfo: AddressInfo
}
function clearCacheItem<T, U extends { expireAt: number }> (map: Map<T, U>) {
  const now = Date.now()
  for (const [key, {expireAt}] of map) {
    if (expireAt < now) {
      map.delete(key)
    }
  }
}

function addr2str (rinfo: AddressInfo) {
  return `${rinfo.address}:${rinfo.port}`
}

function lookup (hostname: string, options: any, callback: (err: Error | null, address: string, family: number) => any) {
  callback(null, hostname, 4)
}

class Peer {
  constructor(public rinfo: AddressInfo){}
}

class PeerManager {
  protected map: Map<string, {
    expireAt: number
    peer: Peer
  }>  = new Map()
  delete (rinfo: AddressInfo) {
    return this.map.delete(addr2str(rinfo))
  }
  get (rinfo: AddressInfo): Peer {
    const key = addr2str(rinfo)
    const map = this.map
    let i = map.get(key)
    if (i === undefined) {
      i = {
        expireAt: Date.now() + Timeout,
        peer: new Peer(rinfo)
      }
      map.set(key, i)
    }
    return i.peer
  }
  clearExpire () {
    clearCacheItem(this.map)
  }
  get size () {
    return this.map.size
  }
  *all (except: AddressInfo) {
    const exceptStr = addr2str(except)
    for (let [key, {peer}] of this.map) {
      if (exceptStr === key) continue
      yield peer
    }
  }
}

export class SLPServer {
  protected server: Socket
  protected ipCache: Map<number, CacheItem> = new Map()
  protected manager: PeerManager = new PeerManager()
  protected byteLastSec = {
    upload: 0,
    download: 0
  }
  constructor (port: number, protected authProvider?: AuthProvider) {
    const server = createSocket({
      type: 'udp4',
      lookup
    })
    server.on('error', (err) => this.onError(err))
    server.on('close', () => this.onClose())
    server.on('message', (msg: Buffer, rinfo: AddressInfo) => this.onMessage(msg, rinfo))
    server.bind(port)
    this.server = server
    setInterval(() => {
      const str = `  Client count: ${this.manager.size} upload: ${this.byteLastSec.upload / 1000}KB/s download: ${this.byteLastSec.download / 1000}KB/s`
      process.stdout.write(str)
      process.stdout.write('\b'.repeat(str.length))
      this.byteLastSec.upload = 0
      this.byteLastSec.download = 0
      this.clearExpire()
    }, 1000)
  }

  public getClientSize() {
    return this.manager.size
  }
  protected parseHead (msg: Buffer): {
    type: ForwarderType,
    isEncrypted: boolean
  } {
    const firstByte = msg.readUInt8(0)
    return {
      type: firstByte & 0x7f,
      isEncrypted: (firstByte & 0x80) !== 0,
    }
  }
  onMessage (msg: Buffer, rinfo: AddressInfo) {
    if (msg.byteLength === 0) {
      return
    }
    this.byteLastSec.download += msg.byteLength

    const { type, isEncrypted } = this.parseHead(msg)
    if (type === ForwarderType.Ping && !isEncrypted) {
      return this.onPing(rinfo, msg)
    }
    let payload = msg.slice(1)

    if (isEncrypted) {
    } else {
      if (this.authProvider) {
        // ignore unencrypted packet when auth is enabled
        return
      }
    }
    const peer = this.manager.get(rinfo)
    this.onPacket(rinfo, type, payload)
  }
  onPacket (rinfo: AddressInfo, type: ForwarderType, payload: Buffer) {
    switch (type) {
      case ForwarderType.Keepalive:
        break
      case ForwarderType.Ipv4:
        this.onIpv4(rinfo, payload)
        break
      case ForwarderType.Ping:
        console.error('never reach here')
        break
      case ForwarderType.Ipv4Frag:
        this.onIpv4Frag(rinfo, payload)
        break
    }
  }
  onIpv4Frag (fromAddr: AddressInfo, payload: Buffer) {
    if (payload.length <= 20) { // packet too short, ignore
      return
    }
    const src = payload.readInt32BE(0)
    const dst = payload.readInt32BE(4)
    this.ipCache.set(src, {
      rinfo: fromAddr,
      expireAt: Date.now() + Timeout
    })
    if (this.ipCache.has(dst)) {
      const { rinfo } = this.ipCache.get(dst)!
      this.sendTo(rinfo, ForwarderType.Ipv4Frag, payload)
    } else {
      this.sendBroadcast(fromAddr, ForwarderType.Ipv4Frag, payload)
    }
  }
  onPing (rinfo: AddressInfo, msg: Buffer) {
    this.sendToRaw(rinfo, msg)
  }
  onIpv4 (fromAddr: AddressInfo, payload: Buffer) {
    if (payload.length <= 20) { // packet too short, ignore
      return
    }
    const src = payload.readInt32BE(IPV4_OFF_SRC)
    const dst = payload.readInt32BE(IPV4_OFF_DST)

    this.ipCache.set(src, {
      rinfo: fromAddr,
      expireAt: Date.now() + Timeout
    })
    if (this.ipCache.has(dst)) {
      const { rinfo } = this.ipCache.get(dst)!
      this.sendTo(rinfo, ForwarderType.Ipv4, payload)
    } else {
      this.sendBroadcast(fromAddr, ForwarderType.Ipv4, payload)
    }
  }
  onError (err: Error) {
    console.log(`server error:\n${err.stack}`)
    this.server.close()
  }
  onSendError (error: Error, bytes: number) {
    console.error(`onSendError ${error} ${bytes}`)
  }
  onClose () {
    console.log(`server closed`)
  }
  sendTo (addr: AddressInfo, type: ForwarderType, payload: Buffer) {
    if (OutputEncrypt) {
      console.warn('not implement')
    }
    this.sendToRaw(addr, Buffer.concat([Buffer.from([type]), payload]))
  }
  sendToRaw (addr: AddressInfo, msg: Buffer) {
    const {address, port} = addr
    this.byteLastSec.upload += msg.byteLength
    this.server.send(msg, port, address, (error, bytes) => {
      if (error) {
        this.manager.delete(addr)
      }
    })
  }
  sendBroadcast (except: AddressInfo, type: ForwarderType, payload: Buffer) {
    for (let peer of this.manager.all(except)) {
      this.sendTo(peer.rinfo, type, payload)
    }
  }
  clearExpire () {
    this.manager.clearExpire()
    clearCacheItem(this.ipCache)
  }
}
