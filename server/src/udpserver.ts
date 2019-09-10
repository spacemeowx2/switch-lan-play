import { createSocket, Socket, AddressInfo } from 'dgram'
import { AuthProvider } from './auth'
import { randomFill as randomFillAsync } from 'crypto'
const randomFill = (buf: Buffer, offset: number) => new Promise((res, rej) => randomFillAsync(buf, offset, (err, buf) => {
  if (err) {
    return rej(err)
  }
  res(buf)
}))
const Timeout = 30 * 1000
const IPV4_OFF_SRC = 12
const IPV4_OFF_DST = 16
const OutputEncrypt = false

enum ForwarderType {
  Keepalive = 0,
  Ipv4 = 1,
  Ping = 2,
  Ipv4Frag = 3,
  AuthMe = 4,
  Info = 0x10,
}
const ForwarderTypeMap: Record<ForwarderType, Buffer> = {
  [ForwarderType.Keepalive]: Buffer.from([ForwarderType.Keepalive]),
  [ForwarderType.Ipv4]: Buffer.from([ForwarderType.Ipv4]),
  [ForwarderType.Ping]: Buffer.from([ForwarderType.Ping]),
  [ForwarderType.Ipv4Frag]: Buffer.from([ForwarderType.Ipv4Frag]),
  [ForwarderType.AuthMe]: Buffer.from([ForwarderType.AuthMe]),
  [ForwarderType.Info]: Buffer.from([ForwarderType.Info]),
}

interface CacheItem {
  expireAt: number
  peer: Peer
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

function lookup4 (hostname: string, options: any, callback: (err: Error | null, address: string, family: number) => any) {
  callback(null, hostname, 4)
}
function lookup6 (hostname: string, options: any, callback: (err: Error | null, address: string, family: number) => any) {
  callback(null, hostname, 6)
}

class User {
  key?: string
  constructor (public username: string) {}
}

class Peer {
  user?: User
  challenge?: Buffer
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
    const expireAt = Date.now() + Timeout
    let i = map.get(key)
    if (i === undefined) {
      i = {
        expireAt,
        peer: new Peer(rinfo)
      }
      map.set(key, i)
    } else {
      i.expireAt = expireAt
    }
    return i.peer
  }
  clearExpire () {
    clearCacheItem(this.map)
  }
  get size () {
    return this.map.size
  }
  getLogin() {
    let count = 0
    for (const i of this.map.values()) {
      if (i.peer.user) {
        count += 1
      }
    }
    return count
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
      type: 'udp6',
      lookup: lookup6
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
    isEncrypted: boolean,
  } {
    const firstByte = msg.readUInt8(0)
    return {
      type: firstByte & 0x7f,
      isEncrypted: (firstByte & 0x80) !== 0,
    }
  }
  async onMessage (msg: Buffer, rinfo: AddressInfo): Promise<void> {
    if (msg.byteLength === 0) {
      return
    }
    this.byteLastSec.download += msg.byteLength

    const { type, isEncrypted } = this.parseHead(msg)
    if (type === ForwarderType.Ping && !isEncrypted) {
      return this.onPing(rinfo, msg)
    }

    const peer = this.manager.get(rinfo)
    let payload = msg.slice(1)

    if (this.authProvider) {
      const { user } = peer
      if (user === undefined) {
        // need to send AuthMe to client
        return this.onNeedAuth(peer, type, payload)
      }
    }
    this.onPacket(peer, type, payload)
  }
  onPacket (peer: Peer, type: ForwarderType, payload: Buffer) {
    switch (type) {
      case ForwarderType.Keepalive:
        break
      case ForwarderType.Ipv4:
        this.onIpv4(peer, payload)
        break
      case ForwarderType.Ping:
        console.error('never reach here')
        break
      case ForwarderType.Ipv4Frag:
        this.onIpv4Frag(peer, payload)
        break
    }
  }
  protected sendInfo (peer: Peer, info: string) {
    this.sendTo(peer, ForwarderType.Info, Buffer.from(info))
  }
  protected async onNeedAuth (peer: Peer, type: ForwarderType, payload: Buffer) {
    if (type === ForwarderType.AuthMe) {
      if (this.authProvider && peer.challenge) {
        if (payload.byteLength <= 20) {
          // no place for username
          return
        }
        const response = payload.slice(0, 20)
        const username = payload.slice(20).toString()
        let err = ''
        try {
          if (await this.authProvider.verify(username, peer.challenge.slice(1), response)) {
            peer.user = new User(username)
          } else {
            err = 'Error when login: Wrong password'
            this.sendInfo(peer, 'Error when login: Wrong password')
          }
        } catch (e) {
          err = `Error when login: ${e.message}`
        }
        if (err.length > 0) {
          console.log(`${err} user: ${username}`)
          this.sendInfo(peer, err)
        }
      }
    } else {
      if (peer.challenge === undefined) {
        const buf = Buffer.alloc(1 + 64)
        peer.challenge = buf
        buf.writeUInt8(0xFF, 0)
        await randomFill(buf, 1)
        buf.writeUInt8(0, 0)
      } else {
        if (peer.challenge.readUInt8(0) === 0xFF) {
          // still filling random bytes
          return
        }
      }

      this.sendTo(peer, ForwarderType.AuthMe, peer.challenge)
    }
  }
  onIpv4Frag (peer: Peer, payload: Buffer) {
    if (payload.length <= 20) { // packet too short, ignore
      return
    }
    const src = payload.readInt32BE(0)
    const dst = payload.readInt32BE(4)
    this.ipCache.set(src, {
      peer,
      expireAt: Date.now() + Timeout
    })
    if (this.ipCache.has(dst)) {
      const { peer } = this.ipCache.get(dst)!
      this.sendTo(peer, ForwarderType.Ipv4Frag, payload)
    } else {
      this.sendBroadcast(peer, ForwarderType.Ipv4Frag, payload)
    }
  }
  onPing (rinfo: AddressInfo, msg: Buffer) {
    this.sendToRaw(rinfo, msg.slice(0, 4))
  }
  onIpv4 (peer: Peer, payload: Buffer) {
    if (payload.length <= 20) { // packet too short, ignore
      return
    }
    const src = payload.readInt32BE(IPV4_OFF_SRC)
    const dst = payload.readInt32BE(IPV4_OFF_DST)

    this.ipCache.set(src, {
      peer,
      expireAt: Date.now() + Timeout
    })
    if (this.ipCache.has(dst)) {
      const { peer } = this.ipCache.get(dst)!
      this.sendTo(peer, ForwarderType.Ipv4, payload)
    } else {
      this.sendBroadcast(peer, ForwarderType.Ipv4, payload)
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
  sendTo ({ rinfo }: Peer, type: ForwarderType, payload: Buffer) {
    if (OutputEncrypt) {
      console.warn('not implement')
    }
    this.sendToRaw(rinfo, Buffer.concat([ForwarderTypeMap[type], payload], payload.byteLength + 1))
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
  sendBroadcast (except: Peer, type: ForwarderType, payload: Buffer) {
    for (let peer of this.manager.all(except.rinfo)) {
      this.sendTo(peer, type, payload)
    }
  }
  clearExpire () {
    this.manager.clearExpire()
    clearCacheItem(this.ipCache)
  }
}
