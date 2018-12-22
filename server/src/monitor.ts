import Koa from 'koa'
import Router, { IRouterContext } from 'koa-router'
import { SLPServer } from './udpserver'
import { join } from 'path'
const pkg = require(join(__dirname, '..', 'package.json'))

export class ServerMonitor {
  private router = new Router()
  private app = new Koa()

  constructor(private server: SLPServer) {
    this.router.all('*', async (ctx, next) => {
      try {
        await next()
      } catch (err) {
        console.error(err)

        ctx.status = err.statusCode || err.status || 500
        ctx.body = {
          error: 'server exceptions'
        }
      }
    })
    this.router.get('/info', async ctx => this.handleGetInfo(ctx))
  }

  public start(port: number) {
	this.app.proxy = true;
    this.app.use(this.router.routes())
    this.app.listen(port, '0.0.0.0')
    console.log(`\nMonitor service started on port ${port}/tcp`)
    console.log(`***************************************`)
  }

  private async handleGetInfo(ctx: IRouterContext) {
    const size = this.server.getClients().size
	const clientIP = ctx.request.ip;
	const current_ip = ctx.ips.length > 0 ? ctx.ips[ctx.ips.length - 1] : ctx.ip;
	const clientes = this.server.getClients();
	let state = "No connected";
	
	clientes.forEach((value, key) => {
		if(key.includes(clientIP)){
			state = value.servicelan;
		}
	});

	
    ctx.type = 'application/json'
    ctx.body = {
      online: size,
	  state: state,
      version: pkg.version
    }
  }
}
