import { BasicAuthProvider, AuthError, AuthErrorType, SHA1 } from './types'

export class CustomAuthProvider extends BasicAuthProvider {
  private sha1: Buffer
  constructor(private username: string, private password: string) {
    super()
    this.sha1 = SHA1(this.password)
  }

  async getUserPasswordSHA1(username: string) {
    if (username !== this.username) {
      throw new AuthError(AuthErrorType.NoSuchUser, 'No such user')
    }
    return this.sha1
  }
}
