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
    options: ThrottlerModuleOptions,            // Конфигурационные параметры для throttler-а (TTL, лимиты и пр.)
    storageService: ThrottlerStorage,           // Сервис для хранения и подсчёта запросов
    reflector: Reflector,                        // Доступ к метаданным NestJS (декораторы и пр.)
    private readonly configService: ConfigService,      // Сервис доступа к конфигурации приложения (env-переменные)
    private readonly securityService: SecurityService,  // Пользовательский сервис безопасности (блокировки, логирование)
  ) {
    // Передаём параметры в конструктор базового класса ThrottlerGuard
    super(options, storageService, reflector);
  }

  /**
   * Метод проверки, разрешён ли текущий запрос с учётом ограничений частоты
   * @param context - контекст выполнения, содержит HTTP-запрос и другую информацию
   * @returns true, если запрос разрешён, иначе выбрасывает ошибку
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Проверяем из конфигурации, включён ли rate limiting для восстановления пароля
    // Ожидается строка 'true' для активации
    const enabled = this.configService.get('RATE_LIMIT_FORGOT_PASSWORD_ENABLED') === 'true';

    // Если ограничение отключено — пропускаем все запросы без лимитов
    if (!enabled) return true;

    // Получаем HTTP-запрос из контекста NestJS
    const req = context.switchToHttp().getRequest();

    // Определяем IP клиента с помощью библиотеки request-ip
    // Если IP не найден — используем значение 'unknown'
    const ip = requestIp.getClientIp(req) || 'unknown';

    // Проверяем, не заблокирован ли IP через SecurityService
    if (this.securityService.isBlocked(ip)) {
      // Если IP заблокирован — отвергаем запрос с ошибкой 403 Forbidden
      throw new ForbiddenException('Доступ с этого IP временно заблокирован.');
    }

    try {
      // Вызываем стандартную логику проверки лимитов из ThrottlerGuard
      // Возвращает true, если лимит не превышен; иначе выбрасывает ThrottlerException
      return await super.canActivate(context);
    } catch (err) {
      // Если произошла ошибка из-за превышения лимита запросов
      if (err instanceof ThrottlerException) {
        // Логируем подозрительную активность с информацией об IP, причине и дополнительными данными запроса
        this.securityService.logSuspiciousActivity(ip, 'Превышен лимит запросов на сброс пароля', {
          userAgent: req.headers['user-agent'],  // User-Agent клиента
          url: req.url,                          // URL запроса
        });
      }
      // Пробрасываем ошибку дальше для её корректной обработки NestJS
      throw err;
    }
  }
}
