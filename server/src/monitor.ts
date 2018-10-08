import Koa from "koa"
import Router, { IRouterContext } from "koa-router"
import { SLPServer } from "./udpserver"

export class ServerMonitor {
  private router = new Router()
  private app = new Koa()
  private server: SLPServer;

  constructor(server: SLPServer) {
    this.server = server;

    this.router.all("*", async (ctx, next) => {
      try {
        await next()
      } catch (err) {
        console.error(err)

        ctx.status = err.statusCode || err.status || 500
        ctx.body = {
          error: "server exceptions"
        }
      }
    })
    this.router.get("/info", async ctx => this.handleGetInfo(ctx))
  }

  public start(port: number) {
    this.app.use(this.router.routes())
    this.app.listen(port || 11480)
    console.log(`\nMonitor service started on port ${port}`)
    console.log(`***************************************`)
  }

  private async handleGetInfo(ctx: IRouterContext) {
    const size = this.server.getClients().size

    ctx.type = "application/json";
    ctx.body = {
      online: size
    }
  }
}
