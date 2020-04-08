import { BasicAuthProvider, AuthError, AuthErrorType, SHA1 } from './types'

export class CustomAuthProvider extends BasicAuthProvider {
  constructor(private username: string, private password: string) {
    super()
  }

  async getUserPasswordSHA1(username: string) {
    if (username !== this.username) {
      throw new AuthError(AuthErrorType.NoSuchUser, 'No such user')
    }
    return Buffer.from(this.password, 'hex')
  }
}
