import { readFile as readFileAsync, watch } from 'fs'
import { promisify } from 'util'
import { BasicAuthProvider, AuthError, AuthErrorType, SHA1 } from './types'
const readFile = promisify(readFileAsync)

type JsonData = Record<string, undefined | string | {
  sha1: string
}>

export class JsonAuthProvider extends BasicAuthProvider {
  private table: JsonData = {}
  constructor (private filename: string) {
    super()
    watch(filename, {
      persistent: false
    }, (event, filename) => {
      console.log(event, filename)
      this.read()
    })
    this.read()
  }
  async read() {
    try {
      this.table = {}
      this.table = JSON.parse(await readFile(this.filename, 'utf-8'))
      this.table['$schema'] = undefined
    } catch (e) {
      console.error(`Fail to parse: ${e}`)
    }
  }
  async getUserPasswordSHA1 (username: string) {
    const pw = this.table[username]
    if (pw === undefined) {
      throw new AuthError(AuthErrorType.NoSuchUser, 'No such user')
    }
    let ret: Buffer
    if (typeof pw === 'string') {
      ret = SHA1(pw)
    } else {
      ret = Buffer.from(pw.sha1, 'hex')
    }
    return ret
  }
}
