import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);

  app.enableCors({
    origin: config.get('APP_URL'),
    credentials: true,
  });
  await app.listen(config.get('APP_PORT') ?? 3000);
}
bootstrap();
