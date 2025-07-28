import { Module } from '@nestjs/common';
import { ThrottlerModule, ThrottlerModuleOptions } from '@nestjs/throttler';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD, Reflector } from '@nestjs/core';

import { IpBlocklistService } from '../ip-blocklist.service';
import { SecurityService } from '../security.service';
import { RateLimitGuard } from '../guards/rate-limit.guard';
import { RegisterRateLimitGuard } from '../guards/register-rate-limit.guard';
import { ForgotPasswordRateLimitGuard } from '../guards/forgot-password-rate-limit.guard';
import { MetricsController } from '../metrics.controller';

@Module({
  // Импортируемые модули, используемые внутри SecurityModule
  imports: [
    ConfigModule, // Модуль для управления конфигурацией приложения (переменные окружения, .env)
    ThrottlerModule.forRootAsync({
      // Асинхронная конфигурация модуля ограничения частоты запросов (rate limiting)
      imports: [ConfigModule],       // Импорт ConfigModule для доступа к конфигурациям
      inject: [ConfigService],       // Внедрение ConfigService для получения переменных окружения
      useFactory: (configService: ConfigService): ThrottlerModuleOptions => {
        // Получаем из конфигурации строку с user-agent-ами, которые нужно игнорировать (например, боты)
        const rawBots = configService.get<string>('THROTTLER_IGNORE_USER_AGENTS', '');
        const ignoreUserAgents = rawBots
          .split(',')              // Разбиваем строку по запятым
          .map(s => s.trim())      // Удаляем лишние пробелы
          .filter(Boolean)         // Удаляем пустые строки
          .map(s => new RegExp(s, 'i')); // Создаём регулярные выражения для игнорируемых user-agent

        // Возвращаем конфигурацию throttler с несколькими профилями лимитов запросов
        return {
          throttlers: [
            {
              ttl: Number(configService.get('RATE_LIMIT_TTL') ?? 60),    // Интервал (в секундах) для учёта запросов (по умолчанию 60 с)
              limit: Number(configService.get('RATE_LIMIT_MAX') ?? 50),  // Максимальное число запросов в указанном интервале (по умолчанию 50)
              name: 'default', // Имя throttler-а — профиль «по умолчанию»
            },
            {
              ttl: Number(configService.get('RATE_LIMIT_REGISTER_TTL') ?? 3600),   // Таймаут лимита для регистрации (например, 1 час)
              limit: Number(configService.get('RATE_LIMIT_REGISTER_MAX') ?? 3),    // Максимум регистраций в этом времени (по умолчанию 3)
              name: 'register', // Имя throttler-а под регистрацию
            },
            {
              ttl: Number(configService.get('RATE_LIMIT_FORGOT_PASSWORD_TTL') ?? 3600), // Таймаут лимита для восстановления пароля
              limit: Number(configService.get('RATE_LIMIT_FORGOT_PASSWORD_MAX') ?? 5),  // Максимум запросов на сброс пароля (по умолчанию 5)
              name: 'forgot-password', // Имя throttler-а для восстановления пароля
            },
          ],
          ignoreUserAgents, // User-agent’ы, которые не будут ограничены лимитами (например, боты)
        };
      },
    }),
  ],

  // Контроллеры, зарегистрированные в модуле
  controllers: [MetricsController], // Контроллер для экспорта метрик Prometheus или других статистик

  // Провайдеры (сервисы, guard’ы и вспомогательные классы), доступные внутри модуля
  providers: [
    IpBlocklistService,   // Сервис для управления блокировкой IP-адресов
    SecurityService,      // Центральный сервис безопасности — логирование, блокировки и пр.
    Reflector,            // Сервис для работы с метаданными (используется в Guard'ах и декораторах)
    {
      provide: APP_GUARD,
      useClass: RateLimitGuard,  // Главный глобальный Guard, отвечающий за ограничение скорости запросов
    },
    RegisterRateLimitGuard,       // Специализированный Guard для ограничения скорости регистрации пользователей
    ForgotPasswordRateLimitGuard, // Guard для ограничения частоты запросов на восстановление пароля
  ],

  // Экспортируемые провайдеры, которые могут использоваться в других модулях приложения
  exports: [
    SecurityService,
    RegisterRateLimitGuard,
    ForgotPasswordRateLimitGuard,
  ],
})
export class SecurityModule {}
