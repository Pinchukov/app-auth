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
// Кастомный Guard для ограничения частоты запросов на сброс пароля (rate limiting)
// Расширяет стандартный ThrottlerGuard из @nestjs/throttler для добавления кастомной логики
export class ForgotPasswordRateLimitGuard extends ThrottlerGuard {
  constructor(
    options: ThrottlerModuleOptions,           // Конфигурационные параметры для throttler-а (TTL, лимиты и пр.)
    storageService: ThrottlerStorage,          // Сервис подсчёта и хранения запросов
    reflector: Reflector,                       // Доступ к метаданным NestJS
    private readonly configService: ConfigService,      // Доступ к env-переменным
    private readonly securityService: SecurityService,  // Сервис безопасности (логирование, блокировка IP)
  ) {
    super(options, storageService, reflector);
  }

  /**
   * Универсальный метод для извлечения булевых значений из конфигурации.
   * Поддерживает значения 'true', '1', 'yes' (без учёта регистра) как true.
   * @param key - имя переменной конфигурации
   * @param defaultValue - значение по умолчанию, если переменная отсутствует
   * @returns boolean
   */
  private getBooleanConfig(key: string, defaultValue = false): boolean {
    const val = this.configService.get<string>(key);
    if (!val) return defaultValue;
    return ['true', '1', 'yes'].includes(val.toLowerCase());
  }

  /**
   * Вспомогательный метод для получения IP клиента из запроса
   * @param req - HTTP-запрос
   * @returns IP-адрес клиента или 'unknown' если не определён
   */
  private getClientIp(req: any): string {
    return requestIp.getClientIp(req) || 'unknown';
  }

  /**
   * Метод проверки, разрешён ли текущий запрос с учётом ограничений частоты
   * @param context - ExecutionContext, содержит HTTP-запрос и другую информацию
   * @returns true, если запрос разрешён, иначе выбрасывает ошибку
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const enabled = this.getBooleanConfig('RATE_LIMIT_FORGOT_PASSWORD_ENABLED');
    if (!enabled) return true;

    const req = context.switchToHttp().getRequest();
    const ip = this.getClientIp(req);

    if (this.securityService.isBlocked(ip)) {
      throw new ForbiddenException('Доступ с этого IP временно заблокирован.');
    }

    try {
      // Базовая логика ограничения по количеству запросов
      return await super.canActivate(context);
    } catch (err: unknown) {
      if (err instanceof ThrottlerException) {
        // Асинхронное логирование подозрительной активности с ожиданием завершения
        await this.securityService.logSuspiciousActivity(ip, 'Превышен лимит запросов на сброс пароля', {
          userAgent: req.headers['user-agent'],
          url: req.url,
        });
      }
      throw err;
    }
  }
}
