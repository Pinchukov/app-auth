import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
// Сервис для работы с логами подозрительной активности
// Отвечает за создание записей в таблице suspiciousActivityLog через Prisma
export class SuspiciousActivityLogService {
  // Внедряем PrismaService для доступа к базе данных
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Создание записи лога подозрительной активности
   *
   * @param data - объект с информацией о подозрительной активности
   *   - ip: IP-адрес, с которого зафиксирована активность (обязательно)
   *   - reason: причина, почему активность считается подозрительной (обязательно)
   *   - userAgent: User-Agent браузера или приложения (опционально)
   *   - url: URL, на котором была зафиксирована активность (опционально)
   *   - userId: ID пользователя, если он известен (опционально)
   *
   * @returns Promise с созданной записью лога из базы данных
   */
  async create(data: {
    ip: string;
    reason: string;
    userAgent?: string;
    url?: string;
    userId?: number;
  }) {
    // Используем Prisma для создания новой записи в таблице suspiciousActivityLog
    return this.prisma.suspiciousActivityLog.create({
      data,
    });
  }
}
