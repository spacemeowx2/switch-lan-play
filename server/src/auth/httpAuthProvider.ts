import axios from 'axios'
import { BasicAuthProvider, AuthError, AuthErrorType } from './types'

interface HttpServerResponse {
  error?: string
  passwordSHA1: string
}

export class HttpAuthProvider extends BasicAuthProvider {
  constructor (private url: string) {
    super()
  }
  async getUserPasswordSHA1(username: string): Promise<Buffer> {
    const url = `${this.url}?username=${encodeURIComponent(username)}`
    const { data: ret } = await axios.get<HttpServerResponse>(url)
    if (ret.error) {
      console.error('http auth', username, ret.error)
      throw new AuthError(AuthErrorType.UpstreamError, 'http auth: upstream error')
    }
    return Buffer.from(ret.passwordSHA1, 'hex')
  }
}
