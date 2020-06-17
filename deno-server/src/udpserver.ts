import { AuthProvider } from './auth/index.ts'
import { concat } from 'https://deno.land/std/bytes/mod.ts'

const randomFill = (buf: Uint8Array, offset: number) => {
  let t = buf.slice(offset)
  crypto.getRandomValues(t)
  buf.set(t, offset)
}
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
const ForwarderTypeMap: Record<ForwarderType, Uint8Array> = {
  [ForwarderType.Keepalive]: Uint8Array.from([ForwarderType.Keepalive]),
  [ForwarderType.Ipv4]: Uint8Array.from([ForwarderType.Ipv4]),
  [ForwarderType.Ping]: Uint8Array.from([ForwarderType.Ping]),
  [ForwarderType.Ipv4Frag]: Uint8Array.from([ForwarderType.Ipv4Frag]),
  [ForwarderType.AuthMe]: Uint8Array.from([ForwarderType.AuthMe]),
  [ForwarderType.Info]: Uint8Array.from([ForwarderType.Info]),
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

function addr2str (rinfo: Deno.NetAddr) {
  return `${rinfo.hostname}:${rinfo.port}`
}

function withTimeout<T> (promise: Promise<T>, ms: number) {
  return new Promise<T>((res, rej) => {
    promise.then(res, rej)
    setTimeout(() => rej(new Error('Timeout')), ms)
  })
}

class User {
  key?: string
  constructor (public username: string) {}
}

class Peer {
  user?: User
  challenge?: Uint8Array
  constructor(public rinfo: Deno.NetAddr){}
}

class PeerManager {
  protected map: Map<string, {
    expireAt: number
    peer: Peer
  }>  = new Map()
  delete (rinfo: Deno.NetAddr) {
    return this.map.delete(addr2str(rinfo))
  }
  get (rinfo: Deno.NetAddr): Peer {
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
  *all (except: Deno.NetAddr) {
    const exceptStr = addr2str(except)
    for (let [key, {peer}] of this.map) {
      if (exceptStr === key) continue
      yield peer
    }
  }
}

export class SLPServer {
  protected server: Deno.DatagramConn
  protected ipCache: Map<number, CacheItem> = new Map()
  protected manager: PeerManager = new PeerManager()
  protected byteLastSec = {
    upload: 0,
    download: 0
  }
  constructor (port: number, protected authProvider?: AuthProvider) {
    const server = Deno.listenDatagram({ port, transport: 'udp' })

    this.server = server
    setInterval(() => {
      const str = `  Client count: ${this.manager.size} upload: ${this.byteLastSec.upload / 1000}KB/s download: ${this.byteLastSec.download / 1000}KB/s`
      Deno.stdout.write(new TextEncoder().encode(str))
      Deno.stdout.write(new TextEncoder().encode('\b'.repeat(str.length)))
      this.byteLastSec.upload = 0
      this.byteLastSec.download = 0
      this.clearExpire()
    }, 1000)
    this.run()
  }

  public async run() {
    while (true) {
      try {
        const [ buf, addr ] = await this.server.receive()
        this.onMessage(buf, addr as Deno.NetAddr)
      } catch (e) {
        this.onError(e)
      }
    }
  }

  public getClientSize() {
    return this.manager.size
  }
  protected parseHead (view: DataView): {
    type: ForwarderType,
    isEncrypted: boolean,
  } {
    const firstByte = view.getUint8(0)
    return {
      type: firstByte & 0x7f,
      isEncrypted: (firstByte & 0x80) !== 0,
    }
  }
  async onMessage (msg: Uint8Array, rinfo: Deno.NetAddr): Promise<void> {
    if (msg.byteLength === 0) {
      return
    }
    this.byteLastSec.download += msg.byteLength
    const view = new DataView(msg.buffer)

    const { type, isEncrypted } = this.parseHead(view)
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
  onPacket (peer: Peer, type: ForwarderType, payload: Uint8Array) {
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
    this.sendTo(peer, ForwarderType.Info, new TextEncoder().encode(info))
  }
  protected async onNeedAuth (peer: Peer, type: ForwarderType, payload: Uint8Array) {
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
          if (await withTimeout(this.authProvider.verify(username, peer.challenge.slice(1), response), 5000)) {
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
        const buf = new Uint8Array(1 + 64)
        const view = new DataView(buf.buffer)
        peer.challenge = buf
        view.setUint8(0xFF, 0)
        await randomFill(buf, 1)
        view.setUint8(0, 0)
      } else {
        if (peer.challenge[0] === 0xFF) {
          // still filling random bytes
          return
        }
      }

      this.sendTo(peer, ForwarderType.AuthMe, peer.challenge)
    }
  }
  onIpv4Frag (peer: Peer, payload: Uint8Array) {
    if (payload.length <= 20) { // packet too short, ignore
      return
    }
    const view = new DataView(payload.buffer)
    const src = view.getInt32(0, false)
    const dst = view.getInt32(4, false)
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
  onPing (rinfo: Deno.NetAddr, msg: Uint8Array) {
    this.sendToRaw(rinfo, msg.slice(0, 5))
  }
  onIpv4 (peer: Peer, payload: Uint8Array) {
    if (payload.length <= 20) { // packet too short, ignore
      return
    }
    const view = new DataView(payload.buffer)
    const src = view.getInt32(IPV4_OFF_SRC, false)
    const dst = view.getInt32(IPV4_OFF_DST, false)

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
  sendTo ({ rinfo }: Peer, type: ForwarderType, payload: Uint8Array) {
    if (OutputEncrypt) {
      console.warn('not implement')
    }
    this.sendToRaw(rinfo, concat(ForwarderTypeMap[type], payload))
  }
  sendToRaw (addr: Deno.NetAddr, msg: Uint8Array) {
    this.byteLastSec.upload += msg.byteLength
    this.server.send(msg, addr).catch((error) => {
      if (error) {
        this.manager.delete(addr)
      }
    })
  }
  sendBroadcast (except: Peer, type: ForwarderType, payload: Uint8Array) {
    for (let peer of this.manager.all(except.rinfo)) {
      this.sendTo(peer, type, payload)
    }
  }
  clearExpire () {
    this.manager.clearExpire()
    clearCacheItem(this.ipCache)
  }
}
