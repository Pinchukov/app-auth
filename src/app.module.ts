import { Module } from '@nestjs/common';                       // Импорт декоратора Module для создания модуля NestJS
import { ServeStaticModule } from '@nestjs/serve-static';      // Модуль для отдачи статических файлов
import { join } from 'path';                                   // Утилита для работы с путями файловой системы
import { ConfigModule } from '@nestjs/config';                 // Модуль для работы с переменными окружения
import { AppController } from './app.controller';              // Главный контроллер приложения
import { AppService } from './app.service';                    // Главный сервис приложения
import { PrismaModule } from './prisma/prisma.module';         // Модуль для работы с Prisma ORM
import { PrismaService } from './prisma/prisma.service';
import { SecurityModule } from './security/security.module';   // Модуль безопасности (например, Guards, Guards)
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { NewsModule } from './news/news.module';

@Module({
  imports: [
    // Загрузка переменных окружения из файла .env, доступных глобально по всему приложению
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      // Здесь можно добавить validationSchema для валидации env переменных
    }),

    // Модуль отдачи статических файлов из папки 'public'
    // Путь вычисляется относительно текущей директории (__dirname), поднимаемся на один уровень и получаем 'public'
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'public'),
      // serveRoot по умолчанию '/', то есть статика будет доступна по корню сервера
    }),
    PrismaModule,     // Инициализация базы данных через Prisma ORM
    AuthModule,       // Аутентификация пользователей
    SecurityModule,   // Безопасность (например, Guards, шифрование)
    UserModule,
    NewsModule,
  ],
  // Контроллеры, обрабатывающие входящие HTTP-запросы
  controllers: [AppController],
  // Провайдеры (сервисы), которые внедряются в классы через DI
  providers: [AppService, PrismaService],
})
export class AppModule { }
