import { Module } from '@nestjs/common';
import { ServeStaticModule } from '@nestjs/serve-static';
import { join } from 'path';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { PrismaService } from './prisma/prisma.service';
import { SecurityModule } from './security/security.module';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { NewsModule } from './news/news.module';

@Module({
  imports: [
    /**
     * Подключение ConfigModule для работы с переменными окружения (.env).
     * 
     * Опция isGlobal: true — делает модуль глобальным, его не нужно импортировать в других модулях.
     * envFilePath — путь к файлу с переменными, здесь по умолчанию '.env'.
     * Можно добавить validationSchema для валидации переменных окружения.
     */
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      // validationSchema: ... (опционально для проверки env)
    }),

    /**
     * ServeStaticModule отвечает за отдачу статических файлов (например, фронтенд или статика).
     * 
     * rootPath — абсолютный путь к папке с публичными ресурсами (например, папка 'public')
     * serveRoot — URL-префикс, с которого будут доступны статические файлы
     */
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'public'),
      serveRoot: '/public',
    }),
    PrismaModule,
    AuthModule,
    SecurityModule,
    UserModule,
    NewsModule,
  ],

  // Корневой контроллер приложения — обрабатывает базовые HTTP-запросы
  controllers: [AppController],

  // Глобальные провайдеры — сервисы, доступные через dependency injection по всему приложению
  providers: [AppService, PrismaService],
})
export class AppModule {}
