import { SLPServer } from './udpserver'
import { ServerMonitor } from './monitor'
import { AuthProvider, JsonAuthProvider, HttpAuthProvider } from './auth'

function main (argv: string[]) {
  let port = argv[0]
  let jsonPath = argv[1]
  if (port === undefined) {
    port = '11451'
  }
  let provider: AuthProvider | undefined
  const { USE_HTTP_PROVIDER } = process.env
  if (USE_HTTP_PROVIDER) {
    provider = new HttpAuthProvider(USE_HTTP_PROVIDER)
    console.log(`using HttpAuthProvider url: ${USE_HTTP_PROVIDER}`)
  } else if (jsonPath) {
    provider = new JsonAuthProvider(jsonPath)
    console.log(`using JsonAuthProvider file: ${jsonPath}`)
  }
  const portNum = parseInt(port)
  let s = new SLPServer(portNum, provider)
  let monitor = new ServerMonitor(s)
  monitor.start(portNum)
}
main(process.argv.slice(2))
