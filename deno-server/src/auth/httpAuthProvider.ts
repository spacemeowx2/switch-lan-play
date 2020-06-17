import { BasicAuthProvider, AuthError, AuthErrorType, fromHexString } from './types.ts'

interface HttpServerResponse {
  error?: string
  passwordSHA1: string
}

export class HttpAuthProvider extends BasicAuthProvider {
  constructor (private url: string) {
    super()
  }
  async getUserPasswordSHA1(username: string): Promise<Uint8Array> {
    const url = `${this.url}?username=${encodeURIComponent(username)}`
    const ret: HttpServerResponse = await (await fetch(url)).json()
    if (ret.error) {
      console.error('http auth', username, ret.error)
      throw new AuthError(AuthErrorType.UpstreamError, 'http auth: upstream error')
    }
    return fromHexString(ret.passwordSHA1)
  }
}
