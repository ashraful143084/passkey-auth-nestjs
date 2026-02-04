import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(@InjectModel('User') private userModel: Model<any>) {}

  async create(email: string, password: string) {
    const hash = await bcrypt.hash(password, 10);
    return this.userModel.create({ email, passwordHash: hash });
  }

  async findByEmail(email: string) {
    return this.userModel.findOne({ email });
  }

  async validate(email: string, password: string) {
    const user = await this.findByEmail(email);
    if (!user) return null;
    const ok = await bcrypt.compare(password, user.passwordHash);
    return ok ? user : null;
  }

  async enablePasskey(userId: string) {
    await this.userModel.updateOne({ _id: userId }, { hasPasskey: true });
  }
}
