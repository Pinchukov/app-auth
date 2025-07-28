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
// Кастомный Guard для глобального ограничения скорости запросов (rate limiting)
// Расширяет стандартный ThrottlerGuard из @nestjs/throttler для добавления кастомной логики
export class RateLimitGuard extends ThrottlerGuard {
  constructor(
    options: ThrottlerModuleOptions,           // Конфигурационные параметры Throttler (TTL, лимиты и т.п.)
    storageService: ThrottlerStorage,          // Сервис хранения счётчиков запросов
    reflector: Reflector,                       // Сервис для доступа к метаданным декораторов
    private readonly configService: ConfigService,  // Сервис доступа к конфигурации приложения (.env)
    private readonly securityService: SecurityService, // Кастомный сервис безопасности (логирование, блокировка IP)
  ) {
    // Вызываем конструктор базового класса с необходимыми параметрами
    super(options, storageService, reflector);
  }

  /**
   * Проверяет, разрешён ли текущий запрос с учётом лимитов
   * @param context - контекст исполнения (содержит HTTP-запрос)
   * @returns true, если запрос разрешён, иначе исключение
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Получаем настройку включения rate limiting из конфигурации (ожидается строка 'true' для включения)
    const enabled = this.configService.get('RATE_LIMIT_ENABLED') === 'true';
    if (!enabled) {
      // Если rate limiting отключён — пропускаем все запросы без ограничений
      return true;
    }

    // Извлекаем HTTP-запрос из контекста
    const req = context.switchToHttp().getRequest();

    // Определяем IP клиента с помощью библиотеки request-ip
    // Если IP не найден, используем 'unknown' для идентификации
    const ip = requestIp.getClientIp(req) || 'unknown';

    // Проверяем, не заблокирован ли IP через сервис безопасности (например, после подозрительной активности)
    if (this.securityService.isBlocked(ip)) {
      // Если IP заблокирован — отклоняем запрос с ошибкой 403 Forbidden
      throw new ForbiddenException('Доступ с этого IP временно заблокирован.');
    }

    try {
      // Вызываем стандартную логику ThrottlerGuard для проверки лимитов запросов
      // Если лимит не превышен — возвращается true, иначе генерируется исключение ThrottlerException
      return await super.canActivate(context);
    } catch (err) {
      // Если ловим исключение, связанное с превышением лимита запросов
      if (err instanceof ThrottlerException) {
        // Логируем подозрительную активность с указанием IP, причины и дополнительной информации
        this.securityService.logSuspiciousActivity(ip, 'Превышен лимит запросов', {
          userAgent: req.headers['user-agent'], // User-Agent клиента
          url: req.url,                         // URL, по которому был запрос
        });
      }

      // Пробрасываем ошибку дальше для стандартной обработки NestJS
      throw err;
    }
  }
}
