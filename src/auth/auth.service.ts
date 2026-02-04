import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from './jwt.service';

@Injectable()
export class AuthService {
  constructor(
    private users: UsersService,
    private jwt: JwtService,
  ) {}

  async register(email: string, password: string) {
    const user = await this.users.create(email, password);
    return { id: user._id };
  }

  async login(email: string, password: string) {
    const user = await this.users.validate(email, password);
    if (!user) throw new Error('Invalid credentials');

    return {
      accessToken: this.jwt.sign({
        sub: user._id,
        amr: ['password'],
      }),
      hasPasskey: user.hasPasskey,
    };
  }
}
