import { Sha1 } from 'https://deno.land/std/hash/sha1.ts'
import { concat, equal } from 'https://deno.land/std/bytes/mod.ts'

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
  verify(username: string, challenge: Uint8Array, response: Uint8Array): Promise<boolean>
}
export abstract class BasicAuthProvider implements AuthProvider {
  async verify(username: string, challenge: Uint8Array, response: Uint8Array): Promise<boolean> {
    const sha1 = await this.getUserPasswordSHA1(username)
    return equal(SHA1(concat(sha1, challenge)), response)
  }
  abstract getUserPasswordSHA1(username: string): Promise<Uint8Array>
}

export function SHA1(data: string | Uint8Array): Uint8Array {
  const hash = new Sha1()
  hash.update(data)
  return new Uint8Array(hash.arrayBuffer())
}

export const fromHexString = (hexString: string) => {
  const m = hexString.match(/.{1,2}/g)
  if (m) {
    return new Uint8Array(m.map(byte => parseInt(byte, 16)))
  }
  return new Uint8Array()
}
