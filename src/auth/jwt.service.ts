import * as jwt from 'jsonwebtoken';

export class JwtService {
  sign(payload: any, options?: jwt.SignOptions) {
    return jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN,
      ...options,
    });
  }
}
