import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe, ClassSerializerInterceptor, Logger } from '@nestjs/common';
import { HttpExceptionFilter } from './security/filters/http-exception.filter';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const logger = new Logger('Bootstrap');
  
  // Получаем ConfigService
  const configService = app.get(ConfigService);

  // Логируем текущую среду
  const environment = process.env.NODE_ENV || 'development';
  logger.log(`🌍 Запуск в режиме: ${environment}`);

  // Используем configService для получения env переменных с дефолтами
  const frontendHost = configService.get<string>('URL_FRONTEND', 'https://node.dvgid.ru');
  const frontendPort = configService.get<number>('PORT_FRONTEND', 10000);
  const backendPort = configService.get<number>('PORT_BACKEND', 10001);

  // Конструируем frontendUrl безопасно
  const frontendUrl = `${frontendHost}:${frontendPort}`;
  //const frontendUrl = `${frontendHost}`;

  logger.log(`🔗 Frontend URL: ${frontendUrl}`);
  logger.log(`🔧 Backend Port: ${backendPort}`);

  // Подключаем cookie-parser middleware (должен идти до enableCors)
  app.use(cookieParser());

  // Настройка CORS для поддержки cookie и разрешённых адресов
  app.enableCors({
    origin: [frontendUrl],
    credentials: true,
    exposedHeaders: ['set-cookie'],
  });

  // Глобальный pipe для валидации и трансформации DTO
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Глобальный интерсептор для сериализации
  const reflector = app.get(Reflector);
  app.useGlobalInterceptors(new ClassSerializerInterceptor(reflector));

  // Глобальный фильтр исключений HttpException
  app.useGlobalFilters(new HttpExceptionFilter());

  // Устанавливаем префикс для всех роутов только в development
  if (environment === 'development') {
    app.setGlobalPrefix('api');
    logger.log(`🔧 Установлен префикс 'api' для development режима`);
  }

  await app.listen(backendPort);

  logger.log(`🚀 Backend запущен на порту ${backendPort}`);
  
  // Логируем правильный URL в зависимости от среды
  const apiUrl = environment === 'development' 
    ? `http://localhost:${backendPort}/api`
    : `http://localhost:${backendPort}`;
  logger.log(`📝 API доступно по адресу: ${apiUrl}`);
}

bootstrap().catch((err) => {
  const logger = new Logger('Bootstrap');
  logger.error('❌ Ошибка при запуске приложения', err);
  process.exit(1);
});