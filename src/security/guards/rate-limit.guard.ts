import {
  Injectable,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import {
  ThrottlerGuard,
  ThrottlerException,
  ThrottlerModuleOptions,
  ThrottlerStorage,
} from '@nestjs/throttler';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import * as requestIp from 'request-ip';
import { SecurityService } from '../security.service';

@Injectable()
// Глобальный Guard для ограничения скорости запросов (rate limiting).
// Расширяет стандартный ThrottlerGuard из @nestjs/throttler и добавляет кастомную логику:
// - проверку включения лимитов из конфигурации
// - блокировку подозрительных IP через SecurityService
// - логирование превышений лимитов
export class RateLimitGuard extends ThrottlerGuard {
  constructor(
    options: ThrottlerModuleOptions,
    storageService: ThrottlerStorage,
    reflector: Reflector,
    private readonly configService: ConfigService,
    private readonly securityService: SecurityService,
  ) {
    super(options, storageService, reflector);
  }

  /**
   * Универсальный метод для чтения булевых настроек из env.
   * Поддерживает различные варианты значения true.
   */
  private getBooleanConfig(key: string, defaultValue = false): boolean {
    const val = this.configService.get<string>(key);
    if (!val) return defaultValue;
    return ['true', '1', 'yes'].includes(val.toLowerCase());
  }

  /**
   * Удобный метод получения IP клиента из запроса с резервным значением.
   */
  private getClientIp(req: any): string {
    const ip = requestIp.getClientIp(req);
    return ip || 'unknown';
  }

  /**
   * Проверяет возможность выполнения запроса с учётом лимитов.
   * Бросает исключения при блокировках или превышениях лимитов.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const enabled = this.getBooleanConfig('RATE_LIMIT_ENABLED');
    if (!enabled) {
      // Если глобальное ограничение скорости отключено — разрешаем все запросы
      return true;
    }

    const req = context.switchToHttp().getRequest();
    const ip = this.getClientIp(req);

    if (this.securityService.isBlocked(ip)) {
      throw new ForbiddenException('Доступ с этого IP временно заблокирован.');
    }

    try {
      return await super.canActivate(context);
    } catch (err) {
      // Проверяем тип ошибки — превышение лимита
      if (err instanceof ThrottlerException) {
        // Логируем подозрительную активность (await для гарантированного выполнения)
        await this.securityService.logSuspiciousActivity(ip, 'Превышен лимит запросов', {
          userAgent: req.headers['user-agent'],
          url: req.url,
        });
      }

      // Пробрасываем ошибку дальше для корректной обработки NestJS
      throw err;
    }
  }
}
