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
    console.log('Verify Body', body);
    const user = body.user || (body.userId ? { id: body.userId } : null);
    if (!user || !user.id) {
      throw new BadRequestException('User object or userId is required in the request body');
    }
    return this.passkeys.finishRegistration(user, body.credential);
  }
}
