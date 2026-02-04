import { Controller, Post, Body } from '@nestjs/common';
import { PasskeyService } from './passkey.service';

@Controller('passkeys')
export class PasskeyController {
  constructor(private passkeys: PasskeyService) {}

  @Post('register/start')
  start(@Body() body) {
    return this.passkeys.startRegistration(body.user);
  }

  @Post('register/finish')
  finish(@Body() body) {
    return this.passkeys.finishRegistration(body.user, body.credential);
  }
}
