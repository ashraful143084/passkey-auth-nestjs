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
  ) { }

  async startRegistration(user: any) {
    const options = await generateRegistrationOptions({
      rpName: process.env.RP_NAME || '',
      rpID: process.env.RP_ID || '',
      userID: new TextEncoder().encode(user.id), // Converted to Uint8Array
      userName: user.email,
    });

    await this.challenges.set(`reg:${user.id}`, options.challenge);

    return options;
  }

  async finishRegistration(user: any, response: any) {
    const challenge = await this.challenges.get(`reg:${user.id}`);

    console.log('Challenge', challenge);

    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge || '',
      expectedOrigin: process.env.RP_ORIGIN || '',
      expectedRPID: process.env.RP_ID,
      requireUserVerification: false,
    });

    if (!verified || !registrationInfo) {
      throw new Error('Passkey registration failed');
    }

    const { credential } = registrationInfo;

    await this.passkeyModel.create({
      userId: user.id,
      credentialId: Buffer.from(credential.id).toString('base64url'),
      publicKey: credential.publicKey,
      counter: credential.counter,
    });

    await this.users.enablePasskey(user.id);
  }
}
