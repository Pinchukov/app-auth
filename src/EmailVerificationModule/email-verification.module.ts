import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { JwtModule } from '@nestjs/jwt';
import { EmailVerificationService } from './email-verification.service';
import { EmailVerificationController } from './email-verification.controller';
import { UserModule } from '../user/user.module';

@Module({
  imports: [
    ConfigModule, // Модуль для работы с переменными окружения и конфигурациями
    UserModule,   // Модуль пользователя, нужен для получения и обновления данных пользователей

    // Конфигурация модуля для отправки email (Mailer)
    MailerModule.forRootAsync({
      imports: [ConfigModule], // Импортируем ConfigModule, чтобы использовать ConfigService для чтения env
      useFactory: async (configService: ConfigService) => ({
        transport: {
          // Настройки SMTP сервера для отправки писем
          host: configService.get<string>('SMTP_HOST'),          // Хост SMTP сервера
          port: Number(configService.get<string>('SMTP_PORT')),  // Порт SMTP сервера (например, 465)
          secure: true, // Используется защищённое соединение (SSL/TLS), обычно для порта 465
          auth: {
            user: configService.get<string>('SMTP_USER'),        // Логин пользователя SMTP
            pass: configService.get<string>('SMTP_PASS'),        // Пароль SMTP
          },
        },
        defaults: {
          // Значения по умолчанию для отправляемых писем
          from: `"${configService.get<string>('SMTP_SENDER_NAME') || 'Auth'}" <${configService.get<string>('SMTP_USER')}>`,
          // Имя отправителя и email
        },
      }),
      inject: [ConfigService], // Внедряем ConfigService для доступа к env
    }),

    // Конфигурация JwtModule для создания и проверки JWT токенов для верификации email
    JwtModule.registerAsync({
      imports: [ConfigModule], // Импорт ConfigModule для доступа к переменным окружения
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET') || 'email-verif-secret',
        // Секретный ключ для подписи JWT, берётся из env или используется значение по умолчанию

        signOptions: {
          // Настройки подписи — время жизни токена
          expiresIn: configService.get<string>('JWT_EMAIL_VERIFICATION_EXPIRATION') || '24h',
        },
      }),
      inject: [ConfigService], // Инъекция ConfigService
    }),
  ],

  // Провайдеры, которые будут зарегистрированы и могут быть инжектированы в другие компоненты этого модуля
  providers: [EmailVerificationService],

  // Контроллеры, которые обрабатывают входящие HTTP запросы, связанные с верификацией email
  controllers: [EmailVerificationController],

  // Экспортируем сервис, чтобы его можно было использовать и в других модулях приложения
  exports: [EmailVerificationService],
})
export class EmailVerificationModule { }
