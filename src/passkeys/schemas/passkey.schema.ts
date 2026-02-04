import { Schema, SchemaFactory, Prop } from '@nestjs/mongoose';

@Schema({ timestamps: true })
export class Passkey {
  @Prop()
  userId: string;

  @Prop()
  credentialId: string;

  @Prop()
  publicKey: string;

  @Prop()
  counter: number;
}

export const PasskeySchema = SchemaFactory.createForClass(Passkey);
