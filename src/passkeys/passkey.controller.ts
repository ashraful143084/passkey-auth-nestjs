import { Controller, Post, Body, BadRequestException } from '@nestjs/common';
import { PasskeyService } from './passkey.service';

@Controller('passkeys')
export class PasskeyController {
  constructor(private passkeys: PasskeyService) { }

  @Post('register')
  start(@Body() body: any) {
    return this.passkeys.startRegistration(body.user);
  }

  @Post('verify')
  finish(@Body() body: any) {
    const user = body.user || (body.userId ? { id: body.userId } : null);
    if (!user || !user.id) {
      throw new BadRequestException('User object or userId is required in the request body');
    }
    return this.passkeys.finishRegistration(user, body.credential);
  }

  @Post('authenticate')
  startAuthenticate(@Body() body: any) {
    // Usernameless/discoverable flow - no user identification needed
    return this.passkeys.getAuthenticationOptions();
  }

  @Post('authenticate/verify')
  async finishAuthenticate(@Body() body: any) {
    if (!body.credential) {
      throw new BadRequestException('Credential is required in the request body');
    }
    // Challenge is optional - we can extract it from clientDataJSON if needed
    return this.passkeys.verifyAuthentication(body, body.challenge);
  }
}
