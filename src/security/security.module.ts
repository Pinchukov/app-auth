import { Module } from '@nestjs/common';
import { ThrottlerModule, ThrottlerModuleOptions } from '@nestjs/throttler';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { PrismaModule } from '../prisma/prisma.module';
import { UserModule } from '../user/user.module';
import { IpBlocklistService } from './ip-blocklist.service';
import { SecurityService } from './security.service';
import { SuspiciousActivityLogService } from './suspicious-activity-log.service';
import { RateLimitGuard } from './guards/rate-limit.guard';
import { RegisterRateLimitGuard } from './guards/register-rate-limit.guard';
import { ForgotPasswordRateLimitGuard } from './guards/forgot-password-rate-limit.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { MetricsController } from './metrics.controller';
import { JwtStrategy } from '../auth/strategies/jwt.strategy';

@Module({
  // Импортируемые модули, используемые внутри этого модуля
  imports: [
    ConfigModule,  // Модуль для работы с конфигурациями (.env и др.)
    PrismaModule,   // Модуль Prisma для работы с БД
    UserModule,    // Модуль пользователей, чтобы использовать сервисы пользователей
    // Настройка модуля ограничения количества запросов (Rate limiting) с асинхронной фабрикой
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule], // Импортируем ConfigModule, чтобы получить доступ к переменным конфигурации
      inject: [ConfigService], // Внедряем ConfigService для получения настроек
      useFactory: (configService: ConfigService): ThrottlerModuleOptions => {
        // Получаем из конфига строку с юзер-агентами, которые нужно игнорировать (например, боты)
        const rawBots = configService.get<string>('THROTTLER_IGNORE_USER_AGENTS', '');
        const ignoreUserAgents = rawBots
          .split(',') // разбиваем по запятой
          .map(s => s.trim()) // удаляем пробелы
          .filter(Boolean)    // убираем пустые строки
          .map(s => new RegExp(s, 'i')); // создаём регулярные выражения для игнорируемых UA (регистронезависимо)

        // Возвращаем конфигурацию throttler-а:
        // Задаём несколько групп с разным таймаутом (ttl) и лимитами (limit) запросов
        return {
          throttlers: [
            {
              ttl: Number(configService.get('RATE_LIMIT_TTL') ?? 60),   // время окна в секундах (по умолчанию 60)
              limit: Number(configService.get('RATE_LIMIT_MAX') ?? 50),// макс. количество запросов в окне
              name: 'default', // имя throttler-а
            },
            {
              ttl: Number(configService.get('RATE_LIMIT_REGISTER_TTL') ?? 3600),     // напр. лимит на регистрацию - 1 час
              limit: Number(configService.get('RATE_LIMIT_REGISTER_MAX') ?? 3),       // макс. 3 попытки на час
              name: 'register', // имя отдельного throttler-а для регистрации
            },
            {
              ttl: Number(configService.get('RATE_LIMIT_FORGOT_PASSWORD_TTL') ?? 3600),  // лимит для забытого пароля - 1 час
              limit: Number(configService.get('RATE_LIMIT_FORGOT_PASSWORD_MAX') ?? 5),    // макс. 5 попыток
              name: 'forgot-password', // имя отдельного throttler-а для восстановления пароля
            },
          ],
          ignoreUserAgents, // список UA, которые не ограничиваются (боты, роботы и т.п.)
        };
      },
    }),
  ],
  // Контроллеры, относящиеся к данному модулю
  controllers: [MetricsController], // Контроллер для метрик (прометеус и т.п.)

  // Провайдеры — сервисы и guard'ы, которые регистрируются в этом модуле и могут инжектироваться
  providers: [
    IpBlocklistService,            // Сервис управления блокировкой IP
    SecurityService,               // Сервис безопасности — логирование, блокировка и т.п.
    SuspiciousActivityLogService,  // Сервис для логов подозрительной активности
    JwtStrategy,                   // Стратегия JWT для аутентификации
    Reflector,                    // Стандартный служебный класс для работы с декораторами и метаданными

    {
      provide: APP_GUARD,         // Регистрация глобального Guard-а для ограничения запросов
      useClass: RateLimitGuard,  // Главный Guard, который использует настройки throttling
    },
    RegisterRateLimitGuard,       // Guard для ограничения роутинга регистрации (отдельный лимит)
    ForgotPasswordRateLimitGuard, // Guard для ограничения восстановления пароля
    RolesGuard,                   // Guard для проверки ролей пользователя (авторизация)
  ],

  // Экспортируем провайдеры, которые могут нужны в других модулях приложения
  exports: [
    SecurityService,
    RegisterRateLimitGuard,
    ForgotPasswordRateLimitGuard,
    SuspiciousActivityLogService,
  ],
})
export class SecurityModule {}
