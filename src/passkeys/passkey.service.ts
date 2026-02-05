import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ChallengeService } from '../common/challenge.service';
import { UsersService } from '../users/users.service';

export class PasskeyService {
  constructor(
    @InjectModel('Passkey') private passkeyModel: Model<any>,
    private challenges: ChallengeService,
    private users: UsersService,
  ) {}

  async startRegistration(user: any) {
    const options = await generateRegistrationOptions({
      rpName: process.env.RP_NAME || '',
      rpID: process.env.RP_ID || '',
      userID: user._id,
      userName: user.email,
    });

    await this.challenges.set(`reg:${user._id}`, options.challenge);

    return options;
  }

  async finishRegistration(user: any, response: any) {
    const challenge = await this.challenges.get(`reg:${user._id}`);

    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge || '',
      expectedOrigin: process.env.RP_ORIGIN || '',
      expectedRPID: process.env.RP_ID,
    });

    if (!verified || !registrationInfo) {
      throw new Error('Passkey registration failed');
    }

    const { credential } = registrationInfo;

    await this.passkeyModel.create({
      userId: user._id,
      credentialId: Buffer.from(credential.id).toString('base64url'),
      publicKey: credential.publicKey,
      counter: credential.counter,
    });

    await this.users.enablePasskey(user._id);
  }
}
