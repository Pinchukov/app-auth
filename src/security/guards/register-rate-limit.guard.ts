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
import { SecurityService } from '../security.service';
import * as requestIp from 'request-ip';

@Injectable()
// Кастомный Guard для ограничения скорости регистрации пользователей (rate limiting)
// Наследуется от стандартного ThrottlerGuard из @nestjs/throttler
export class RegisterRateLimitGuard extends ThrottlerGuard {
  constructor(
    options: ThrottlerModuleOptions,      // Параметры конфигурации throttler-а (например, TTL, лимиты)
    storageService: ThrottlerStorage,     // Хранилище для учёта количества запросов
    reflector: Reflector,                  // Сервис для чтения метаданных декораторов
    private readonly configService: ConfigService,     // Сервис для доступа к конфигу (.env)
    private readonly securityService: SecurityService, // Кастомный сервис безопасности, например, для блокировки IP и логирования
  ) {
    // Вызываем конструктор базового класса с необходимыми параметрами
    super(options, storageService, reflector);
  }

  /**
   * Проверка возможности активации Guard-а для текущего запроса
   * @param context - ExecutionContext, содержит объект запроса
   * @returns true, если запрос разрешён, иначе выбрасывает ошибку
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Проверяем включён ли rate limiting для регистрации в конфигурации (строка 'true' -> true)
    const enabled = this.configService.get('RATE_LIMIT_REGISTER_ENABLED') === 'true';
    if (!enabled) {
      // Если ограничение отключено — разрешаем любой запрос без ограничений
      return true;
    }

    // Получаем объект HTTP запроса из контекста
    const req = context.switchToHttp().getRequest();

    // Получаем IP пользователя из запроса с помощью библиотеки request-ip
    // Если IP не определён — используем значение 'unknown'
    const ip = requestIp.getClientIp(req) || 'unknown';

    // Проверяем, не заблокирован ли этот IP по механизму SecurityService
    if (this.securityService.isBlocked(ip)) {
      // Если IP заблокирован — выбрасываем исключение 403 Forbidden
      throw new ForbiddenException('Доступ с этого IP временно заблокирован.');
    }

    try {
      // Вызываем стандартную логику ограничения запросов из базового класса
      // Возвращает true, если лимит не превышен, иначе выбрасывает ThrottlerException
      return await super.canActivate(context);
    } catch (err) {
      // Если произошла ошибка лимитирования (превышен лимит запросов)
      if (err instanceof ThrottlerException) {
        // Логируем подозрительную активность через SecurityService с причиной и дополнительной информацией
        this.securityService.logSuspiciousActivity(ip, 'Превышен лимит регистрации', {
          userAgent: req.headers['user-agent'], // User-Agent из заголовков запроса
          url: req.url,                        // URL запроса
        });
      }
      // Перекидываем ошибку дальше для корректной обработки NestJS
      throw err;
    }
  }
}
