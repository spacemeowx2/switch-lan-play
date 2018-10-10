import { ServerMonitor } from './monitor'
import { createSocket, Socket, AddressInfo } from 'dgram'
type IPAddr = string
const Timeout = 30 * 1000
const IPV4_OFF_SRC = 12
const IPV4_OFF_DST = 16

enum ForwarderType {
  Keepalive = 0,
  Ipv4 = 1,
  Ping = 2,
}

interface CacheItem {
  expireAt: number
  rinfo: AddressInfo
}
function clearCacheItem<T> (map: Map<T, CacheItem>) {
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

function lookup (hostname: string, options: any, callback: (err: Error, address: string, family: number) => any) {
  callback(null, hostname, 4)
}

export class SLPServer {
  server: Socket
  clients: Map<string, CacheItem> = new Map()
  ipCache: Map<number, CacheItem> = new Map()
  byteLastSec: number = 0
  constructor (port: number) {
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
      const str = `  Client count: ${this.clients.size} ${this.byteLastSec / 1000}KB/s`
      process.stdout.write(str)
      process.stdout.write('\b'.repeat(str.length))
      this.byteLastSec = 0
      this.clearExpire()
    }, 1000)
  }

  public getClients() {
    return this.clients
  }

  onMessage (msg: Buffer, rinfo: AddressInfo) {
    if (msg.byteLength === 0) {
      return
    }
    this.byteLastSec += msg.byteLength

    const type: ForwarderType = msg.readUInt8(0)
    if (type != ForwarderType.Ping) {
      this.clients.set(addr2str(rinfo), {
        expireAt: Date.now() + Timeout,
        rinfo
      })
    }
    this.onPacket(rinfo, type, msg.slice(1), msg)
    // this.sendBroadcast(rinfo, msg)
  }
  onPacket (rinfo: AddressInfo, type: ForwarderType, payload: Buffer, msg: Buffer) {
    switch (type) {
      case ForwarderType.Keepalive:
        break
      case ForwarderType.Ipv4:
        this.onIpv4(rinfo, payload, msg)
        break
      case ForwarderType.Ping:
        this.onPing(rinfo, payload, msg)
        break
    }
  }
  onPing (rinfo: AddressInfo, payload: Buffer, msg: Buffer) {
    this.sendTo(rinfo, msg)
  }
  onIpv4 (fromAddr: AddressInfo, payload: Buffer, msg: Buffer) {
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
      const { rinfo } = this.ipCache.get(dst)
      this.sendTo(rinfo, msg)
    } else {
      this.sendBroadcast(fromAddr, msg)
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
  sendTo (addr: AddressInfo, data: Buffer) {
    const {address, port} = addr
    this.byteLastSec += data.byteLength
    this.server.send(data, port, address, (error, bytes) => {
      if (error) {
        this.clients.delete(addr2str(addr))
      }
    })
  }
  sendBroadcast (except: AddressInfo, data: Buffer) {
    let exceptStr = addr2str(except)
    for (let [key, {rinfo}] of this.clients) {
      if (exceptStr === key) continue
      this.sendTo(rinfo, data)
    }
  }
  clearExpire () {
    clearCacheItem(this.clients)
    clearCacheItem(this.ipCache)
  }
}

function main (argv: string[]) {
  let port = argv[0]
  if (port === undefined) {
    port = '11451'
  }
  const portNum = parseInt(port)
  let s = new SLPServer(portNum)
  let monitor = new ServerMonitor(s)
  monitor.start(portNum)
}
main(process.argv.slice(2))
