import { Module } from '@nestjs/common';
// Импорт декоратора Module из NestJS для создания модуля

import { ConfigModule, ConfigService } from '@nestjs/config';
// Импорт модуля конфигурации и сервиса для доступа к переменным окружения

import { MailerModule } from '@nestjs-modules/mailer';
// Модуль для отправки email сообщений

import { JwtModule } from '@nestjs/jwt';
// Модуль для работы с JWT (JSON Web Token)

import { EmailVerificationService } from './email-verification.service';
// Сервис, реализующий логику верификации email

import { EmailVerificationController } from './email-verification.controller';
// Контроллер, обрабатывающий HTTP-запросы по верификации email

import { UserModule } from '../user/user.module';
// Модуль пользователей, возможно для проверки или получения данных пользователя


@Module({
  imports: [
    ConfigModule,
    // Импорт модуля конфигурации для доступа к настройкам из env

    UserModule,
    // Импорт пользовательского модуля, чтобы работать с пользователями внутри email verification

    MailerModule.forRootAsync({
      imports: [ConfigModule],
      // Импорт ConfigModule внутри MailerModule для доступа к настройкам почты

      useFactory: async (configService: ConfigService) => ({
        transport: {
          // Настройки для SMTP транспорта (сервер для отправки почты)
          host: configService.get<string>('SMTP_HOST'),
          port: Number(configService.get<string>('SMTP_PORT')),
          secure: true, // Использование защищённого соединения (SSL/TLS)
          auth: {
            user: configService.get<string>('SMTP_USER'),
            pass: configService.get<string>('SMTP_PASS'),
          },
        },
        defaults: {
          // Значения по умолчанию для отправителя письма
          from: `"${configService.get<string>('SMTP_SENDER_NAME') || 'Auth'}" <${configService.get<string>('SMTP_USER')}>`,
        },
      }),
      inject: [ConfigService],
      // Внедрение сервиса ConfigService для динамической настройки
    }),

    JwtModule.registerAsync({
      imports: [ConfigModule],
      // Импорт ConfigModule для доступа к jwt-настройкам

      useFactory: (configService: ConfigService) => ({
        // Настройки JWT для email верификации
        secret: configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET') || 'email-verif-secret',
        signOptions: {
          // Время действия токена верификации (по умолчанию 24 часа)
          expiresIn: configService.get<string>('JWT_EMAIL_VERIFICATION_EXPIRATION') || '24h',
        },
      }),
      inject: [ConfigService],
      // Внедрение ConfigService для получения значений из переменных окружения
    }),
  ],
  providers: [EmailVerificationService],
  // Провайдеры (сервисы), которые будут использованы внутри модуля

  controllers: [EmailVerificationController],
  // Контроллеры для обработки HTTP-запросов

  exports: [EmailVerificationService],
  // Экспорт сервиса для использования в других модулях
})
export class EmailVerificationModule {}
// Объявление и экспорт модуля email верификации
