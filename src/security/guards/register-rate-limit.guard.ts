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
// Кастомный Guard, который расширяет стандартный ThrottlerGuard
// и реализует ограничение скорости конкретно для регистрации пользователей
export class RegisterRateLimitGuard extends ThrottlerGuard {
  constructor(
    options: ThrottlerModuleOptions,       // Конфигурационные опции throttler (TTL, лимиты и т.п.)
    storageService: ThrottlerStorage,      // Сервис-хранилище для учёта количества запросов
    reflector: Reflector,                   // Сервис для работы с метаданными NestJS
    private readonly configService: ConfigService,      // Сервис для доступа к переменным окружения (.env)
    private readonly securityService: SecurityService,  // Кастомный сервис безопасности (блокировка IP, логирование)
  ) {
    // Вызываем конструктор базового класса с параметрами
    super(options, storageService, reflector);
  }

  /**
   * Универсальный метод для безопасного получения булевых переменных из конфигурации (.env)
   * Позволяет учитывать значения 'true', '1', 'yes' (без учёта регистра) как true
   * @param key - имя переменной окружения
   * @param defaultValue - значение по умолчанию, если переменная не установлена
   * @returns boolean значение переменной
   */
  private getBooleanConfig(key: string, defaultValue = false): boolean {
    const val = this.configService.get<string>(key);
    if (!val) return defaultValue;
    return ['true', '1', 'yes'].includes(val.toLowerCase());
  }

  /**
   * Главный метод Guards — проверяет, разрешён ли данный запрос
   * @param context - ExecutionContext от NestJS, содержит информацию о текущем запросе
   * @returns Promise<boolean> — разрешён ли доступ
   *
   * Логика:
   * - Проверяет, включено ли ограничение скорости регистрации
   * - Получает IP пользователя из запроса
   * - Проверяет, не заблокирован ли IP
   * - Вызывает базовую логику throttling из ThrottlerGuard
   * - Если лимит превышен, логирует подозрительную активность
   * - В случае блокировки IP или превышения лимита выбрасывает исключения
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Получаем флаг включения лимита из конфигурации надёжным методом
    const enabled = this.getBooleanConfig('RATE_LIMIT_REGISTER_ENABLED');
    if (!enabled) {
      // Если ограничение выключено — всегда разрешаем запрос
      return true;
    }

    // Получаем обьект HTTP запроса из ExecutionContext
    const req = context.switchToHttp().getRequest();

    // Получаем IP-клиента с помощью библиотеки request-ip, если IP не определён — 'unknown'
    const ip = requestIp.getClientIp(req) || 'unknown';

    // Проверяем, заблокирован ли IP через securityService
    if (this.securityService.isBlocked(ip)) {
      // Если IP в блоке — выбрасываем исключение HTTP 403 Forbidden
      throw new ForbiddenException('Доступ с этого IP временно заблокирован.');
    }

    try {
      // Выполняем стандартную логику throttling (ограничения скорости)
      // Если лимит не превышен — возвращает true
      // Если превышен — выбрасывает ThrottlerException
      return await super.canActivate(context);
    } catch (err) {
      // Если было исключение throttling (превышение лимита)
      if (err instanceof ThrottlerException) {
        // Логируем подозрительную активность с информацией по IP, user-agent и адресу запроса
        this.securityService.logSuspiciousActivity(ip, 'Превышен лимит регистрации', {
          userAgent: req.headers['user-agent'],  // User-Agent клиента
          url: req.url,                           // URL запроса
        });
      }
      // Пробрасываем ошибку дальше для корректной обработки NestJS
      throw err;
    }
  }
}
