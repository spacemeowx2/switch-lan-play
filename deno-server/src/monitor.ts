import { createApp, ServerRequest } from 'https://deno.land/x/servest/mod.ts'
import { cors } from 'https://deno.land/x/servest/middleware/cors.ts'
import { SLPServer } from './udpserver.ts'
import { Version } from './version.ts'

export class ServerMonitor {
  private app = createApp()

  constructor(private server: SLPServer) {
  }

  public start(port: number) {
    this.app.use(cors({
      origin: /./g
    }))
    this.app.route('/info', async ctx => this.handleGetInfo(ctx))
    this.app.listen({ port })
    console.log(`\nMonitor service started on port ${port}/tcp`)
    console.log(`***************************************`)
  }

  private async handleGetInfo(req: ServerRequest) {
    const size = this.server.getClientSize()

    req.respond({
      status: 200,
      headers: new Headers({
        'content-type': 'application/json',
      }),
      body: JSON.stringify({
        online: size,
        version: Version
      }),
    })
  }
}
