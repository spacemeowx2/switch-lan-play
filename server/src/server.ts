import {createServer, Server, Socket} from 'net'

class SLPHandler {
  private buf: Buffer = new Buffer(0)
  private waitLen: number = -1
  id: number
  constructor (private socket: Socket, private server: SLPServer) {
    socket.on('data', (data) => this.onData(data))
    console.log('new SLPHandler')
    socket.on('close', () => {
      console.error(`SLPHandler: close`)
      server.onHandlerClose(this)
    })
    socket.on('error', (err) => {
      console.error(`SLPHandler:`, err)
    })
    this.id = server.getNextID()
  }
  private onData (data: Buffer) {
    this.buf = Buffer.concat([this.buf, data])
    if (this.buf.byteLength < 4) {
      return
    }
    if (this.waitLen === -1) {
      this.waitLen = this.buf.readUInt32BE(0) + 4
    }
    if (this.buf.byteLength >= this.waitLen) {
      const data = this.buf.slice(4, this.waitLen)
      this.buf = this.buf.slice(this.waitLen)
      this.waitLen = -1
      this.onPacket(data)
    }
  }
  onPacket (p: Buffer) {
    console.log(p)
    this.server.sendBroadcast(this, p)
  }
  send (buf: Buffer) {
    const header = new ArrayBuffer(4)
    if (buf.byteLength > 0) {
      new DataView(header).setUint32(0, buf.byteLength, false)
      this.socket.write(new Buffer(header))
      this.socket.write(buf)
    }
  }
}

class SLPServer {
  server: Server
  clients: Set<SLPHandler> = new Set()
  private nextID = 1
  constructor (port: number) {
    const server = createServer()
    server.on('connection', (socket) => this.onConnection(socket))
    server.on('error', (err) => this.onError(err))
    server.on('close', () => this.onClose())
    server.listen(port)
    this.server = server
    setInterval(() => {
      console.log(`Client count: ${this.clients.size}`)
    }, 1000)
  }
  getNextID () {
    return this.nextID++
  }
  onConnection (socket: Socket) {
    const handler = new SLPHandler(socket, this)
    this.clients.add(handler)
  }
  onError (err: Error) {
    console.log(`server error:\n${err.stack}`)
    this.server.close()
  }
  onClose () {
    console.log(`server closed`)
  }
  onHandlerClose (handler: SLPHandler) {
    this.clients.delete(handler)
  }
  sendBroadcast (except: SLPHandler, data: any) {
    for (let c of this.clients) {
      if (c === except) continue
      c.send(data)
    }
  }
}
let s = new SLPServer(11451)
