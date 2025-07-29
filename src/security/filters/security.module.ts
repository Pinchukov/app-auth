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

/**
 * SecurityModule — отвечает за:
 * - блокировку IP-адресов
 * - глобальное и специализированное ограничение скорости запросов (rate limiting)
 * - логирование подозрительной активности
 * - предоставление метрик для мониторинга
 */
@Module({
  imports: [
    ConfigModule,
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService): ThrottlerModuleOptions => {
        // Функция для безопасного парсинга числовых переменных окружения с дефолтом
        const getNumberEnv = (key: string, defaultValue: number): number => {
          const val = configService.get<string>(key);
          const num = Number(val);
          return isNaN(num) ? defaultValue : num;
        };

        const rawBots = configService.get<string>('THROTTLER_IGNORE_USER_AGENTS', '');
        const ignoreUserAgents = rawBots
          .split(',')
          .map(s => s.trim())
          .filter(Boolean)
          .map(s => {
            try {
              return new RegExp(s, 'i');
            } catch {
              // Можно добавить логирование ошибки, для дебага некорректного паттерна
              return null;
            }
          })
          .filter((re): re is RegExp => re !== null);

        return {
          throttlers: [
            {
              ttl: getNumberEnv('RATE_LIMIT_TTL', 60),
              limit: getNumberEnv('RATE_LIMIT_MAX', 50),
              name: 'default',
            },
            {
              ttl: getNumberEnv('RATE_LIMIT_REGISTER_TTL', 3600),
              limit: getNumberEnv('RATE_LIMIT_REGISTER_MAX', 3),
              name: 'register',
            },
            {
              ttl: getNumberEnv('RATE_LIMIT_FORGOT_PASSWORD_TTL', 3600),
              limit: getNumberEnv('RATE_LIMIT_FORGOT_PASSWORD_MAX', 5),
              name: 'forgot-password',
            },
          ],
          ignoreUserAgents,
        };
      },
    }),
  ],
  controllers: [MetricsController],
  providers: [
    IpBlocklistService,
    SecurityService,
    Reflector,
    {
      provide: APP_GUARD,
      useClass: RateLimitGuard,
    },
    RegisterRateLimitGuard,
    ForgotPasswordRateLimitGuard,
  ],
  exports: [SecurityService, RegisterRateLimitGuard, ForgotPasswordRateLimitGuard],
})
export class SecurityModule {}
