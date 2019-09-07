import { SLPServer } from './udpserver'
import { ServerMonitor } from './monitor'

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
