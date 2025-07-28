import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe, ClassSerializerInterceptor } from '@nestjs/common';
import { HttpExceptionFilter } from './security/filters/http-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Глобальный pipe для валидации и трансформации DTO
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Глобальный интерсептор для сериализации (@Exclude и @Expose в DTO)
  const reflector = app.get(Reflector);
  app.useGlobalInterceptors(new ClassSerializerInterceptor(reflector));

  // Глобальный фильтр исключений HttpException
  app.useGlobalFilters(new HttpExceptionFilter());

  app.setGlobalPrefix('api');
  app.use(cookieParser());

  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:10000';

  app.enableCors({
    origin: [frontendUrl],
    credentials: true,
    exposedHeaders: ['set-cookie'],
  });

  const port = process.env.PORT ? Number(process.env.PORT) : 10005;
  await app.listen(port);

  console.log(`🚀 Backend запущен на порту ${port}`);
}

bootstrap();
