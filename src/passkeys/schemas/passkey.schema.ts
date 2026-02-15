import { Schema, SchemaFactory, Prop } from '@nestjs/mongoose';

@Schema({ timestamps: true })
export class Passkey {
  @Prop()
  userId: string;

  @Prop()
  credentialId: string; // Base64URL encoded credential ID

  @Prop()
  publicKey: string; // Base64 encoded public key

  @Prop()
  counter: number;

  @Prop()
  name: string; // User-friendly name (e.g. "My MacBook")

  @Prop({ type: [String] })
  transports: string[]; // ['usb', 'nfc', 'ble', 'internal']

  @Prop()
  userAgent: string; // Browser/Device details during registration
}

export const PasskeySchema = SchemaFactory.createForClass(Passkey);
