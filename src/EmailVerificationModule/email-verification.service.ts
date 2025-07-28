import { Injectable, BadRequestException, NotFoundException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../user/user.service';

// Интерфейс полезной нагрузки (payload) для токена верификации email
export interface EmailVerificationPayload {
  sub: number;     // ID пользователя
  email: string;   // email пользователя
}

// DTO для ответа при верификации email
export interface VerifyEmailResponseDto {
  message: string; // Текстовое сообщение о результате верификации
}

@Injectable()
export class EmailVerificationService {
  // Логгер для записи событий и ошибок сервиса
  private readonly logger = new Logger(EmailVerificationService.name);

  constructor(
    private readonly jwtService: JwtService,           // Сервис для работы с JWT (создание и проверка токенов)
    private readonly mailerService: MailerService,     // Сервис для отправки email
    private readonly userService: UserService,         // Сервис для работы с пользователями (поиск, обновление)
    private readonly configService: ConfigService,     // Сервис для чтения переменных окружения
  ) { }

  /**
   * Генерирует JWT-токен для подтверждения email пользователя.
   * @param userId - ID пользователя
   * @param email - email пользователя
   * @returns Promise<string> - подписанный JWT с payload и временем жизни
   */
  async generateEmailVerificationToken(userId: number, email: string): Promise<string> {
    const payload: EmailVerificationPayload = { sub: userId, email };
    // Время жизни токена берется из переменной окружения или по умолчанию 24 часа
    const expiresIn = this.configService.get<string>('JWT_EMAIL_VERIFICATION_EXPIRATION') || '24h';
    const secret = this.configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET');
    // Подписываем токен асинхронно с заданным секретом и сроком жизни
    return this.jwtService.signAsync(payload, { secret, expiresIn });
  }

  /**
   * Строит URL для подтверждения email с токеном в параметрах.
   * Использует базовый URL бекенда из конфигурации или локальный адрес по умолчанию.
   * @param token - токен для подтверждения
   * @returns string - полный URL для подтверждения email
   */
  private buildVerificationUrl(token: string): string {
    const baseUrl = this.configService.get<string>('BACKEND_URL') ?? 'http://localhost:10005';
    return `${baseUrl}/api/auth/verify?token=${token}`;
  }

  /**
   * Формирует HTML-шаблон письма с ссылкой подтверждения email.
   * Включает логотип и базовое приветствие.
   * @param verificationUrl - ссылка подтверждения
   * @returns string - HTML-содержимое письма
   */
  private buildVerificationEmailHtml(verificationUrl: string): string {
    const logoUrl = this.configService.get<string>('EMAIL_LOGO_URL') ?? 'http://localhost:10005/public/logo_120.png';

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

  /**
   * Отправляет email с письмом для подтверждения адреса.
   * Проверяет, включена ли верификация email; если нет — логирует и выходит без отправки.
   * @param email - адрес получателя
   * @param token - токен подтверждения для вставки в ссылку
   */
  async sendVerificationEmail(email: string, token: string) {
    const isEnabled = this.configService.get<string>('EMAIL_VERIFICATION_ENABLED') === 'true';
    if (!isEnabled) {
      this.logger.log('Email verification отключён, письмо не отправляется');
      return;
    }

    const verificationUrl = this.buildVerificationUrl(token);
    const fromEmail = this.configService.get<string>('SMTP_USER') ?? 'no-reply@example.com';
    const senderName = this.configService.get<string>('SMTP_SENDER_NAME') || 'Auth';

    try {
      await this.mailerService.sendMail({
        to: email,
        from: `"${senderName}" <${fromEmail}>`,
        subject: 'Подтвердите ваш email',
        html: this.buildVerificationEmailHtml(verificationUrl),
      });
      this.logger.log(`Письмо с подтверждением отправлено на ${email}`);
    } catch (error) {
      this.logger.error(`Ошибка при отправке подтверждения на ${email}`, error.stack || error.message);
      throw error;
    }
  }

  /**
   * Отправляет email с письмом для сброса пароля.
   * Формирует ссылку на фронтенд с токеном сброса.
   * @param email - адрес получателя
   * @param token - токен сброса пароля
   */
  async sendResetPasswordEmail(email: string, token: string) {
    const frontendUrl = this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:10000';
    const resetUrl = `${frontendUrl}/reset-password?token=${token}`;

    const fromEmail = this.configService.get<string>('SMTP_USER') ?? 'no-reply@example.com';
    const senderName = this.configService.get<string>('SMTP_SENDER_NAME') || 'Auth';

    const html = `
      <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333;">
        <p>Вы запросили сброс пароля.</p>
        <p>Нажмите на ссылку, чтобы изменить пароль:</p>
        <p><a href="${resetUrl}">${resetUrl}</a></p>
        <p>Если вы не инициировали запрос — просто проигнорируйте это письмо.</p>
      </div>
    `;

    try {
      await this.mailerService.sendMail({
        to: email,
        from: `"${senderName}" <${fromEmail}>`,
        subject: 'Сброс пароля',
        html,
      });
      this.logger.log(`Письмо для сброса пароля успешно отправлено на ${email}`);
    } catch (error) {
      this.logger.error(`Ошибка при отправке письма сброса пароля на ${email}`, error.stack || error.message);
      throw error;
    }
  }

  /**
   * Проверяет валидность и срок действия токена подтверждения email.
   * Если верификация выключена — сразу возвращает соответствующее сообщение.
   * После успешной верификации меняет статус пользователя.
   * @param token - JWT токен подтверждения email
   * @returns Promise<VerifyEmailResponseDto> - результат с сообщением успеха или ошибки
   */
  async verifyEmailToken(token: string): Promise<VerifyEmailResponseDto> {
    const isEnabled = this.configService.get<string>('EMAIL_VERIFICATION_ENABLED') === 'true';
    if (!isEnabled) {
      this.logger.log('Email verification отключён, пропускаем проверку токена');
      return { message: 'Email verification отключён' };
    }

    try {
      // Проверяем и декодируем токен, извлекая payload
      const payload = await this.jwtService.verifyAsync<EmailVerificationPayload>(token);

      // Ищем пользователя по email из токена
      const user = await this.userService.findByEmail(payload.email);
      if (!user) {
        this.logger.warn(`Пользователь с email ${payload.email} не найден при подтверждении`);
        throw new NotFoundException('Пользователь не найден');
      }

      // Если пользователь уже подтверждён, просто возвращаем сообщение
      if (user.status) {
        this.logger.log(`Email ${payload.email} уже подтверждён`);
        return { message: 'Email уже подтверждён' };
      }

      // Обновляем статус пользователя на подтверждённый
      await this.userService.update(user.id, { status: true });
      this.logger.log(`Email ${payload.email} успешно подтверждён`);
      return { message: 'Email успешно подтверждён' };
    } catch (error) {
      // Ошибка при неверном или истёкшем токене
      this.logger.warn('Неверный или истёкший токен подтверждения', error.stack || error.message);
      throw new BadRequestException('Неверный или истёкший токен подтверждения');
    }
  }
}
