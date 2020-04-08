import { SLPServer } from './udpserver'
import { ServerMonitor } from './monitor'
import { AuthProvider, JsonAuthProvider, HttpAuthProvider } from './auth'
import { CustomAuthProvider } from "./auth/CustomAuthProvider";

function startServer(argv: string[], port: string | undefined, username: string | undefined, password: string | undefined) {
  if (!port) {
    port = argv[0] || '11451';
  }
  let jsonPath = argv[1];
  let provider: AuthProvider | undefined
  const {USE_HTTP_PROVIDER} = process.env
  if (USE_HTTP_PROVIDER) {
    provider = new HttpAuthProvider(USE_HTTP_PROVIDER)
    console.log(`using HttpAuthProvider url: ${USE_HTTP_PROVIDER}`)
  } else if (jsonPath) {
    provider = new JsonAuthProvider(jsonPath)
    console.log(`using JsonAuthProvider file: ${jsonPath}`)
  } else if (username && password) {
    provider = new CustomAuthProvider(username, password);
    console.log(`using custom auth with username=${username} password=******`);
  }
  const portNum = parseInt(port)
  let s = new SLPServer(portNum, provider)
  let monitor = new ServerMonitor(s)
  monitor.start(portNum)
}

function main(argv: string[]) {
  const readLine = require('readline');
  const rl = readLine.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  let port: string | undefined;
  const getPort = () => {
    return new Promise((resolve, reject) => {
      rl.question('Please input the server port(default is 11451 or your first parameter) :', (answer: string) => {
        port = answer;
        resolve();
      })
    })
  }

  let username: string | undefined;
  const getUsername = () => {
    return new Promise((resolve, reject) => {
      rl.question('Please input the auth username(default is empty) :', (answer: string) => {
        username = answer;
        resolve();
      })
    })
  }

  let password: string | undefined;
  const getPassword = () => {
    return new Promise((resolve, reject) => {
      rl.question('Please input the auth password(default is empty) :', (answer: string) => {
        password = answer;
        resolve();
      })
    })
  }

  const go = async () => {
    await getPort();
    await getUsername();
    await getPassword();
    startServer(argv, port, username, password);
    rl.close();
  }

  go();
}

main(process.argv.slice(2))
