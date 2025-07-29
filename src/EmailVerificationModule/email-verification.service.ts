// Импорт необходимых классов и декораторов из NestJS и других модулей
import { Injectable, Logger, BadRequestException, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';

// Интерфейс полезной нагрузки (payload) JWT для подтверждения email
export interface EmailVerificationPayload {
  sub: number;   // Идентификатор пользователя (userId)
  email: string; // Адрес электронной почты пользователя
}

// DTO (Data Transfer Object): определяет структуру ответа при успешной верификации email
export interface VerifyEmailResponseDto {
  message: string; // Сообщение для клиента
}

@Injectable() // Помечаем класс как инжектируемый сервис для использования в других местах приложения
export class EmailVerificationService {
  private readonly logger = new Logger(EmailVerificationService.name); // Логгер для ведения логов

  // Приватные поля для хранения конфигурационных данных
  private readonly emailVerificationSecret: string;
  private readonly emailVerificationEnabled: boolean;
  private readonly backendUrl: string;
  private readonly frontendUrl: string;

  // Конструктор, в который через DI (Dependency Injection) передаются необходимые сервисы
  constructor(
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
    private readonly userService: UserService,
    private readonly configService: ConfigService,
  ) {
    // Получаем секрет для JWT из конфигурации
    const secret = this.configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET');
    if (!secret) {
      // Если секрет не задан, выбрасываем ошибку сразу в конструкторе
      throw new Error('JWT_EMAIL_VERIFICATION_SECRET must be defined');
    }
    this.emailVerificationSecret = secret;

    // Получаем, включена ли верификация email (true/false)
    this.emailVerificationEnabled = this.getBooleanConfig('EMAIL_VERIFICATION_ENABLED');

    // Формируем URL бекенда (протокол + адрес + порт)
    const backendBaseUrl = this.configService.get<string>('URL_BACKEND') ?? 'http://localhost';
    const backendPort = this.configService.get<string>('PORT_BACKEND') ?? '10010';
    this.backendUrl = `${backendBaseUrl}:${backendPort}`;

    // Формируем URL фронтенда (протокол + адрес + порт)
    const frontendBaseUrl = this.configService.get<string>('URL_FRONTEND') ?? 'http://localhost';
    const frontendPort = this.configService.get<string>('PORT_FRONTEND') ?? '10020';
    this.frontendUrl = `${frontendBaseUrl}:${frontendPort}`;
  }

  // Вспомогательный метод для получения булевого значения из конфигурации (строка 'true', '1', 'yes' => true)
  private getBooleanConfig(key: string, defaultValue = false): boolean {
    const val = this.configService.get<string>(key);
    if (!val) return defaultValue;
    return ['true', '1', 'yes'].includes(val.toLowerCase());
  }

  // Генерирует JWT токен для подтверждения email с полезной нагрузкой и временем жизни
  async generateEmailVerificationToken(userId: number, email: string): Promise<string> {
    const payload: EmailVerificationPayload = { sub: userId, email };
    // Время жизни токена, например '24h', из конфигурации (по умолчанию сутки)
    const expiresIn = this.configService.get<string>('JWT_EMAIL_VERIFICATION_EXPIRATION') ?? '24h';
    // Создаём и подписываем JWT асинхронно
    return this.jwtService.signAsync(payload, {
      secret: this.emailVerificationSecret,
      expiresIn,
    });
  }

  // Формирует URL для перехода пользователем для подтверждения email
  private buildVerificationUrl(token: string): string {
    // Ссылка на эндпоинт бекенда с параметром токена, который нужно подтвердить
    return `${this.backendUrl}/api/auth/verify?token=${encodeURIComponent(token)}`;
  }

  // Формирует поле "from" для письма в формате "Имя <email>"
  private getMailerFrom() {
    const fromEmail = this.configService.get<string>('SMTP_USER') ?? 'no-reply@example.com';
    const senderName = this.configService.get<string>('SMTP_SENDER_NAME') || 'Auth';
    return `"${senderName}" <${fromEmail}>`;
  }

  // Формирует HTML-шаблон письма для подтверждения email с логотипом и ссылкой
  private buildVerificationEmailHtml(verificationUrl: string): string {
    // Логотип для письма (из настроек или по умолчанию)
    const logoUrl = this.configService.get<string>('EMAIL_LOGO_URL') ?? `${this.backendUrl}/logo_120.png`;

    // Сам HTML письма
    return `
      <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333;">
        <div style="text-align: center; margin-bottom: 20px;">
          <img src="${logoUrl}" alt="Логотип" style="width: 120px; height: auto;" />
        </div>
        <p>Спасибо за регистрацию! Чтобы подтвердить ваш email, пожалуйста, перейдите по ссылке:</p>
        <p><a href="${verificationUrl}" style="color: #0654ba;">${verificationUrl}</a></p>
        <p>Если вы не регистрировались — просто проигнорируйте это письмо.</p>
      </div>
    `;
  }

  // Отправляет письмо с ссылкой на подтверждение email
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    // Если верификация отключена, просто логируем и не отправляем письмо
    if (!this.emailVerificationEnabled) {
      this.logger.log('Email verification отключён, письмо не отправляется');
      return;
    }

    // Формируем URL с токеном
    const verificationUrl = this.buildVerificationUrl(token);

    try {
      // Отправляем письмо через mailerService
      await this.mailerService.sendMail({
        to: email,
        from: this.getMailerFrom(),
        subject: 'Подтвердите ваш email',
        html: this.buildVerificationEmailHtml(verificationUrl),
      });
      this.logger.log(`Письмо с подтверждением отправлено на ${email}`);
    } catch (error) {
      // Логируем ошибку, если не удалось отправить письмо, и повторно выбрасываем её
      this.logger.error(`Ошибка при отправке подтверждения на ${email}`, error instanceof Error ? error.stack : String(error));
      throw error;
    }
  }

  // Отправляет письмо для сброса пароля с уникальным токеном
  async sendResetPasswordEmail(email: string, token: string): Promise<void> {
    // Формируем URL для сброса пароля на фронтенде
    const resetUrl = `${this.frontendUrl}/reset-password?token=${encodeURIComponent(token)}`;

    // HTML письмо для сброса пароля
    const html = `
      <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333;">
        <p>Вы запросили сброс пароля.</p>
        <p>Нажмите на ссылку, чтобы изменить пароль:</p>
        <p><a href="${resetUrl}">${resetUrl}</a></p>
        <p>Если вы не инициировали запрос — просто проигнорируйте это письмо.</p>
      </div>
    `;

    try {
      // Отправляем письмо
      await this.mailerService.sendMail({
        to: email,
        from: this.getMailerFrom(),
        subject: 'Сброс пароля',
        html,
      });
      this.logger.log(`Письмо для сброса пароля успешно отправлено на ${email}`);
    } catch (error) {
      // Логируем ошибки отправки и повторно выбрасываем
      this.logger.error(`Ошибка при отправке письма сброса пароля на ${email}`, error instanceof Error ? error.stack : String(error));
      throw error;
    }
  }

  // Метод для проверки и обработки токена подтверждения email
  async verifyEmailToken(token: string): Promise<VerifyEmailResponseDto> {
    // Если верификация отключена, логируем и возвращаем сообщение, что проверка пропускается
    if (!this.emailVerificationEnabled) {
      this.logger.log('Email verification отключён, пропускаем проверку токена');
      return { message: 'Email verification отключён' };
    }

    try {
      // Верифицируем JWT токен по секрету и достаём полезную нагрузку
      const payload = await this.jwtService.verifyAsync<EmailVerificationPayload>(token, {
        secret: this.emailVerificationSecret,
      });

      // Ищем пользователя по email из полезной нагрузки токена
      const user = await this.userService.findByEmail(payload.email);
      if (!user) {
        // Если пользователь не найден — логируем и выбрасываем ошибку 404
        this.logger.warn(`Пользователь с email ${payload.email} не найден при подтверждении`);
        throw new NotFoundException('Пользователь не найден');
      }

      // Если пользователь уже подтверждён — логируем и возвращаем соответствующее сообщение
      if (user.status) {
        this.logger.log(`Email ${payload.email} уже подтверждён`);
        return { message: 'Email уже подтверждён' };
      }

      // Обновляем статус пользователя — помечаем email как подтверждённый
      await this.userService.update(user.id, { status: true });
      this.logger.log(`Email ${payload.email} успешно подтверждён`);
      return { message: 'Email успешно подтверждён' };
    } catch (error) {
      // Если токен невалидный или истёк — логируем и выбрасываем BadRequestException
      this.logger.warn('Неверный или истёкший токен подтверждения', error instanceof Error ? error.stack : String(error));
      throw new BadRequestException('Неверный или истёкший токен подтверждения');
    }
  }
}
