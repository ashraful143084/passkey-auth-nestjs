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
import { AuthService } from '../auth/auth.service';
import { generateChallenge } from '@simplewebauthn/server/helpers';
import { UnauthorizedException, BadRequestException, Injectable } from '@nestjs/common';


@Injectable()
export class PasskeyService {
  constructor(
    @InjectModel('Passkey') private passkeyModel: Model<any>,
    private challenges: ChallengeService,
    private users: UsersService,
    private authService: AuthService,
  ) { }



  async startRegistration(user: any) {
    const options = await generateRegistrationOptions({
      rpName: process.env.RP_NAME || '',
      rpID: process.env.RP_ID || '',
      userID: new TextEncoder().encode(user.id), // Converted to Uint8Array
      userName: user.email,
      userDisplayName: user.email,
    });

    await this.challenges.set(`reg:${user.id}`, options.challenge);

    return options;
  }

  async finishRegistration(user: any, response: any, name: string, userAgent: string) {
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
      credentialId: credential.id, // ID is already Base64URL encoded from verifyRegistrationResponse
      publicKey: Buffer.from(credential.publicKey).toString('base64'),
      counter: credential.counter,
      name: name || 'Unknown Device',
      transports: response.response.transports || [],
      userAgent: userAgent,
    });

    await this.users.enablePasskey(user.id);
  }

  async getAuthenticationOptions() {
    const challengeBytes = await generateChallenge();
    const challenge = Buffer.from(challengeBytes).toString('base64url');

    // Store challenge in Redis with a temporary key
    // Since we don't know the user yet, use a global challenge store
    await this.challenges.set(`auth:global:${challenge}`, challenge);

    return {
      challenge: challenge,
      rpId: process.env.RP_ID || '',
      allowCredentials: [], // Empty array = usernameless/discoverable flow
      userVerification: 'preferred',
      timeout: 60000
    };
  }

  async verifyAuthentication(body: any, expectedChallenge?: string) {
    const { credential } = body;
    console.log('Credential received:', JSON.stringify(credential, null, 2));

    // 1. Get userId from credential.response.userHandle
    const userHandleBase64 = credential.response.userHandle;
    if (!userHandleBase64) {
      throw new UnauthorizedException('User handle not found in credential response');
    }

    // Decode the base64-encoded userHandle to get the actual userId
    // Ensure input is properly padded before decoding if it's raw base64url
    const userId = Buffer.from(userHandleBase64, 'base64').toString('utf-8');


    // 3. Get the challenge - either from parameter or extract from clientDataJSON
    let challenge = expectedChallenge;
    if (!challenge) {
      // Decode clientDataJSON to extract the challenge
      const clientDataJSON = JSON.parse(
        Buffer.from(credential.response.clientDataJSON, 'base64').toString('utf-8')
      );
      challenge = clientDataJSON.challenge;
    }

    if (!challenge) {
      throw new UnauthorizedException('Challenge not found');
    }

    // Normalize Base64URL strings
    // Convert any Base64 variant (+/ or -_) to canonical Base64URL
    const toBase64Url = (str: string) => {
      if (!str) return str;
      // 1. Replace Base64URL chars with standard Base64 chars
      let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      // 2. Add padding
      while (base64.length % 4) {
        base64 += '=';
      }
      return Buffer.from(base64, 'base64').toString('base64url');
    };

    const normalizedResponse = {
      ...credential.response,
      authenticatorData: toBase64Url(credential.response.authenticatorData),
      clientDataJSON: toBase64Url(credential.response.clientDataJSON),
      signature: toBase64Url(credential.response.signature),
      userHandle: credential.response.userHandle ? toBase64Url(credential.response.userHandle) : undefined,
    };

    // Also normalize the top-level ID and rawId just in case
    const normalizedCredential = {
      ...credential,
      id: toBase64Url(credential.id),
      rawId: toBase64Url(credential.rawId),
      response: normalizedResponse
    };

    console.log('Looking up passkey for userId:', userId, 'and credentialId:', normalizedCredential.id);

    // 2. Fetch the user's passkey from database using userId AND credentialId
    let userPasskey = await this.passkeyModel.findOne({ 
      userId, 
      credentialId: normalizedCredential.id 
    });

    // Backward compatibility: If not found, try double-encoded version (base64url of base64url)
    if (!userPasskey) {
      const doubleEncodedId = Buffer.from(normalizedCredential.id).toString('base64url');
      console.log('Passkey not found with standard ID, trying double-encoded:', doubleEncodedId);
      userPasskey = await this.passkeyModel.findOne({ 
        userId, 
        credentialId: doubleEncodedId 
      });
    }

    if (!userPasskey) {
      console.error('Passkey NOT found in DB. Total passkeys for this user:');
      const allUserPasskeys = await this.passkeyModel.find({ userId });
      console.log(allUserPasskeys.map(p => ({ id: p.credentialId, name: p.name })));
      throw new UnauthorizedException('Passkey not found for user: ' + userId + ' with credential: ' + normalizedCredential.id);
    }

    try {
      // 4. Verify the authentication
      const verification = await verifyAuthenticationResponse({
        response: normalizedCredential,
        expectedChallenge: challenge,
        expectedOrigin: process.env.RP_ORIGIN || '',
        expectedRPID: process.env.RP_ID || '',
        credential: {
          id: userPasskey.credentialId,
          publicKey: (() => {
            const buffer = Buffer.from(userPasskey.publicKey, 'base64');
            return buffer;
          })(),
          counter: userPasskey.counter,
        },
        requireUserVerification: false,
      });

      if (verification.verified) {
        // 4. Update counter in database
        await this.passkeyModel.updateOne(
          { userId },
          { counter: verification.authenticationInfo.newCounter }
        );

        // 5. Get user details
        const user = await this.users.findById(userId);

        if (!user) {
          throw new UnauthorizedException('User not found');
        }

        // Clean up challenge
        if (expectedChallenge) {
          await this.challenges.del(`auth:global:${expectedChallenge}`);
        }
        // Also try cleaning up user specific challenge if it exists (though for usernameless it might be global)
        // For clarity we just clean what we used.

        return {
          verified: true,
          user: {
            id: String(user._id),
            email: user.email,
            accessToken: this.authService.generateAccessToken(user),
            refreshToken: this.authService.generateRefreshToken(user),
          },
          passkey: {
            name: userPasskey.name,
            userAgent: userPasskey.userAgent,
          }
        };
      }
    } catch (error) {
      console.error('Verification failed:', error);
      throw new BadRequestException('Passkey verification failed: ' + error.message);
    }

    return { verified: false };
  }

  async getUserPasskeys(userId: string) {
    return this.passkeyModel.find({ userId }).sort({ createdAt: -1 }).exec();
  }
}
