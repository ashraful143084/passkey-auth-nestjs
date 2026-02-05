import { Controller, Post, Body } from '@nestjs/common';
import { PasskeyService } from './passkey.service';

@Controller('/api/auth/passkeys')
export class PasskeyController {
  constructor(private passkeys: PasskeyService) {}

  @Post('/register')
  start(@Body() body: any) {
    return this.passkeys.startRegistration(body.user);
  }

  @Post('/verify')
  finish(@Body() body: any) {
    return this.passkeys.finishRegistration(body.user, body.credential);
  }
}
