import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

/**
 * PrismaService расширяет PrismaClient и интегрируется с жизненным циклом NestJS.
 * 
 * Это позволяет автоматически устанавливать и закрывать соединение с базой данных
 * при старте и завершении работы модуля.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  
  /**
   * Метод вызывается при инициализации модуля (например, старте приложения).
   * Здесь происходит подключение к базе данных.
   */
  async onModuleInit() {
    await this.$connect();
  }

  /**
   * Метод вызывается при уничтожении модуля (например, остановке приложения).
   * Здесь происходит корректное закрытие соединения с базой данных.
   */
  async onModuleDestroy() {
    await this.$disconnect();
  }
}
