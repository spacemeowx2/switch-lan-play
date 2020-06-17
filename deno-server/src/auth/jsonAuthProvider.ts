import { BasicAuthProvider, AuthError, AuthErrorType, SHA1, fromHexString } from './types.ts'

type JsonData = Record<string, undefined | string | {
  sha1: string
}>

export class JsonAuthProvider extends BasicAuthProvider {
  private table: JsonData = {}
  constructor (private filename: string) {
    super()
    this.run(filename)
    this.read()
  }
  async run(filename: string) {
    const watcher = Deno.watchFs(filename)
    for await (const event of watcher) {
      console.log(event, filename)
      this.read()
    }
  }
  async read() {
    try {
      this.table = {}
      this.table = JSON.parse(new TextDecoder().decode(await Deno.readFile(this.filename)))
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
    let ret: Uint8Array
    if (typeof pw === 'string') {
      ret = SHA1(pw)
    } else {
      ret = fromHexString(pw.sha1)
    }
    return ret
  }
}
