import { SLPServer } from './udpserver'
import { ServerMonitor } from './monitor'
import { AuthProvider, JsonAuthProvider } from './auth'

function main (argv: string[]) {
  let port = argv[0]
  let jsonPath = argv[1]
  if (port === undefined) {
    port = '11451'
  }
  let provider: AuthProvider | undefined
  if (jsonPath) {
    provider = new JsonAuthProvider(jsonPath)
    console.log(`using jsonProvider file: ${jsonPath}`)
  }
  const portNum = parseInt(port)
  let s = new SLPServer(portNum, provider)
  let monitor = new ServerMonitor(s)
  monitor.start(portNum)
}
main(process.argv.slice(2))
