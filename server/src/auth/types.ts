import { createHash } from 'crypto'

export enum AuthErrorType {
  NoSuchUser,
  UpstreamError
}
export class AuthError extends Error {
  constructor (public type: AuthErrorType, message?: string) {
    super(message)
  }
}
export interface AuthProvider {
  verify(username: string, challenge: Buffer, response: Buffer): Promise<boolean>
}
export abstract class BasicAuthProvider implements AuthProvider {
  async verify(username: string, challenge: Buffer, response: Buffer): Promise<boolean> {
    const sha1 = await this.getUserPasswordSHA1(username)
    return SHA1(Buffer.concat([sha1, challenge])).equals(response)
  }
  abstract getUserPasswordSHA1(username: string): Promise<Buffer>
}

export function SHA1(data: string | Buffer): Buffer {
  const hash = createHash('SHA1')
  hash.update(data)
  return hash.digest()
}
