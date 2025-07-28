import { Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

/**
 * PrismaModule — модуль NestJS, отвечающий за организацию доступа к базе данных
 * через Prisma ORM.
 * 
 * Здесь регистрируется PrismaService, который инкапсулирует логику подключения
 * и взаимодействия с базой данных.
 * 
 * Экспортируем PrismaService, чтобы другие модули могли использовать его через
 * механизм Dependency Injection.
 */
@Module({
  // Провайдеры модуля — сервисы, которые будут созданы и доступны внутри модуля
  providers: [PrismaService],

  // Экспортируем провайдера, чтобы он был доступен и в других модулях приложения
  exports: [PrismaService],
})
export class PrismaModule {}
