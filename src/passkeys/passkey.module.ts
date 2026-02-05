import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { PasskeySchema } from './schemas/passkey.schema';
import { PasskeyService } from './passkey.service';
import { PasskeyController } from './passkey.controller';
import { ChallengeService } from '../common/challenge.service';
import { UsersModule } from '../users/users.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: 'Passkey', schema: PasskeySchema }]),
    UsersModule,
    AuthModule,
  ],
  providers: [PasskeyService, ChallengeService],
  controllers: [PasskeyController],
})
export class PasskeyModule { }
