import {createSocket, Socket, AddressInfo} from 'dgram'
const Timeout = 30 * 1000

interface CacheItem {
  time: number
  rinfo: AddressInfo
}

function addr2str (rinfo: AddressInfo) {
  return `${rinfo.address}:${rinfo.port}`
}

class SLPServer {
  server: Socket
  clients: Map<string, CacheItem> = new Map()
  byteLastSec: number = 0
  constructor (port: number) {
    const server = createSocket('udp4')
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
  onMessage (msg: Buffer, rinfo: AddressInfo) {
    this.clients.set(addr2str(rinfo), {
      time: Date.now(),
      rinfo
    })
    this.sendBroadcast(rinfo, msg)
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
  sendBroadcast (except: AddressInfo, data: Buffer) {
    let exceptStr = addr2str(except)
    for (let [key, {rinfo: {address, port}}] of this.clients) {
      if (exceptStr === key) continue
      this.server.send(data, port, address, (error, bytes) => {
        this.clients.delete(key)
      })
    }
  }
  clearExpire () {
    const clients = this.clients
    const now = Date.now()
    for (const [key, {time}] of clients) {
      if (now - time > Timeout) {
        clients.delete(key)
      }
    }

  }
}
let s = new SLPServer(11451)
