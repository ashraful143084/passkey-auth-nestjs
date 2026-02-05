import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from './jwt.service';

@Injectable()
export class AuthService {
  constructor(
    private users: UsersService,
    private jwt: JwtService,
  ) { }

  async register(email: string, password: string) {
    const user = await this.users.create(email, password);
    return { id: user._id };
  }

  async login(email: string, password: string) {
    const user = await this.users.validate(email, password);
    if (!user) throw new Error('Invalid credentials');

    return {
      accessToken: this.generateAccessToken(user),
      refreshToken: this.generateRefreshToken(user),
      hasPasskey: user.hasPasskey,
      user: user,
    };
  }

  generateAccessToken(user: any) {
    return this.jwt.sign({
      sub: user._id,
      email: user.email,
      amr: ['password'], // or 'passkey' if applicable, maybe make this dynamic?
    });
  }

  generateRefreshToken(user: any) {
    // For now, simple JWT for refresh token too, or whatever logic is preferred
    return this.jwt.sign({
      sub: user._id,
      type: 'refresh',
    }, { expiresIn: '7d' });
  }
}
