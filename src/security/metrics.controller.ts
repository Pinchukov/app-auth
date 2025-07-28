import { Controller, Get, Header, UseGuards } from '@nestjs/common';
import * as client from 'prom-client';  // Клиент Prometheus для сбора и экспорта метрик
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/guards/roles.decorator';
import { Role } from '@prisma/client';

@Controller('metrics')
// Защищаем все маршруты контроллера аутентификацией и авторизацией по ролям
@UseGuards(JwtAuthGuard, RolesGuard)
export class MetricsController {
  /**
   * Эндпоинт для получения метрик Prometheus
   * Метод GET /metrics
   * Доступен только для пользователей с ролью ADMIN
   *
   * @returns Promise<string> - текстовый вывод метрик в формате Prometheus
   */
  @Get()
  @Roles(Role.ADMIN)  // Доступ только для администраторов
  // Устанавливаем заголовок Content-Type согласно формату Prometheus (text/plain; version=0.0.4)
  @Header('Content-Type', client.register.contentType)
  getMetrics(): Promise<string> {
    // Получаем все собранные метрики в виде текста
    return client.register.metrics();
  }
}
