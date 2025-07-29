import {
  Injectable,
  ForbiddenException,
  UnauthorizedException,
  ConflictException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { Role } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UserService } from '../user/user.service';
import { EmailVerificationService } from '../EmailVerificationModule/email-verification.service';

@Injectable()
// Основной сервис аутентификации, отвечающий за регистрацию, логин, обновление токенов и восстановление пароля
export class AuthService {
  // Время жизни токенов считывается из конфигурации
  private readonly jwtAccessExpiry: string;
  private readonly jwtRefreshExpiry: string;
  private readonly jwtResetPwdExpiry: string;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private userService: UserService,
    private emailVerificationService: EmailVerificationService,
    private configService: ConfigService,
  ) {
    // Получаем параметры из конфигурации
    this.jwtAccessExpiry = this.configService.get<string>('JWT_ACCESS_TOKEN_EXPIRATION', '15m');
    this.jwtRefreshExpiry = this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRATION', '7d');
    this.jwtResetPwdExpiry = this.configService.get<string>('JWT_RESET_PASSWORD_EXPIRATION', '15m');
  }

  // Метод для создания JWT access и refresh токенов для пользователя
  async getTokens(
    userId: number,
    email: string,
    role: Role,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    // Генерируем сразу два токена параллельно
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, email, role }, // payload токена
        {
          secret: this.configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
          expiresIn: this.jwtAccessExpiry,
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, email, role },
        {
          secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
          expiresIn: this.jwtRefreshExpiry,
        },
      ),
    ]);
    return { accessToken, refreshToken };
  }

  // Сохраняет в базе хэш refresh токена пользователя
  async updateRefreshToken(userId: number, refreshToken: string): Promise<void> {
    const hashed = await argon2.hash(refreshToken);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hashed },
    });
  }

  // Обновляет токены доступа и обновления по существующему refresh токену
  async refreshTokens(
    userId: number,
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    // Находим пользователя и проверяем наличие сохранённого refresh токена
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true, refreshToken: true },
    });

    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Доступ запрещён');
    }

    // Проверяем валидность переданного refresh токена
    const isValid = await argon2.verify(user.refreshToken, refreshToken);
    if (!isValid) {
      throw new ForbiddenException('Доступ запрещён');
    }

    // Генерируем новые токены и обновляем сохранённый refresh токен
    const tokens = await this.getTokens(user.id, user.email, user.role);
    await this.updateRefreshToken(user.id, tokens.refreshToken);
    return tokens;
  }

  // Выполняет logout — удаляет сохранённый refresh токен у пользователя
  async logout(userId: number): Promise<void> {
    if (!userId) {
      throw new BadRequestException('userId is required for logout');
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException(`Пользователь с id ${userId} не найден`);
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });
  }

  // Логин пользователя с проверкой email, пароля и статуса аккаунта
  async login(dto: LoginDto): Promise<{ accessToken: string; refreshToken: string }> {
    // Проверяем, разрешён ли сейчас вход в систему по конфигу
    const loginEnabled = this.configService.get<string>('LOGIN_ENABLED') === 'true';
    if (!loginEnabled) {
      throw new ForbiddenException('Авторизация в данный момент недоступна');
    }

    // Ищем пользователя по email
    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (!user) {
      throw new UnauthorizedException('Неверный email или пароль');
    }

    // Проверяем правильность пароля
    const passwordMatches = await argon2.verify(user.password, dto.password);
    if (!passwordMatches) {
      throw new UnauthorizedException('Неверный email или пароль');
    }

    // Если включена проверка email, убеждаемся, что пользователь активен
    const emailVerificationEnabled = this.configService.get<string>('EMAIL_VERIFICATION_ENABLED') === 'true';
    if (emailVerificationEnabled && !user.status) {
      throw new ForbiddenException('Пользователь не активен');
    }

    // Генерируем токены и обновляем refresh токен в БД
    const tokens = await this.getTokens(user.id, user.email, user.role);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  // Регистрация нового пользователя с проверкой возможности создания и уникальности email
  async register(dto: RegisterDto) {
    // Проверка возможности регистрации из конфигурации
    const registrationEnabled = this.configService.get<string>('REGISTRATION_ENABLED') === 'true';
    if (!registrationEnabled) {
      throw new ForbiddenException('Регистрация в данный момент недоступна');
    }

    // Проверка, что пользователь с таким email ещё не существует
    const existingUser = await this.userService.findByEmail(dto.email);
    if (existingUser) {
      throw new ConflictException('Пользователь с таким email уже существует');
    }

    // Определяем необходимость подтверждения email
    const emailVerificationEnabled = this.configService.get<string>('EMAIL_VERIFICATION_ENABLED') === 'true';

    // Создаём нового пользователя
    const user = await this.userService.create({
      name: dto.name,
      email: dto.email,
      password: dto.password,
      status: !emailVerificationEnabled, // если включена проверка, пользователь не активен до подтверждения
      role: Role.USER,
    });

    if (emailVerificationEnabled) {
      // Если нужен verification email — отправляем ссылку с токеном
      const token = await this.emailVerificationService.generateEmailVerificationToken(user.id, user.email);
      await this.emailVerificationService.sendVerificationEmail(user.email, token);
      return {
        message: 'Регистрация успешна! Пожалуйста, подтвердите email, перейдя по ссылке в письме.',
      };
    }

    // Если не нужен подтверждающий email — сразу создаём и возвращаем токены
    const tokens = await this.getTokens(user.id, user.email, user.role);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
      },
      tokens,
    };
  }

  // Запрос на восстановление пароля — отправляет письмо со ссылкой для сброса на email пользователя если он найден
  async forgotPassword(dto: ForgotPasswordDto) {
    // Проверяем возможность сброса пароля из конфига
    const resetEnabled = this.configService.get<string>('RESET_PASSWORD_ENABLED') === 'true';
    if (!resetEnabled) {
      throw new ForbiddenException('Восстановление пароля временно недоступно');
    }

    // Ищем пользователя по email
    const user = await this.userService.findByEmail(dto.email);
    if (!user) {
      // Если пользователя нет, ничего не делаем (например, чтобы не выдать инфо)
      return;
    }

    // Создаём токен сброса пароля с коротким сроком жизни
    const token = await this.jwtService.signAsync(
      { sub: user.id },
      {
        secret: this.configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET'),
        expiresIn: this.jwtResetPwdExpiry,
      },
    );

    // Отправляем письмо с ссылкой для сброса пароля
    await this.emailVerificationService.sendResetPasswordEmail(user.email, token);
  }

  // Сброс пароля по токену и новому паролю
  async resetPassword(dto: ResetPasswordDto) {
    // Проверка возможности сброса пароля из конфига
    const resetEnabled = this.configService.get<string>('RESET_PASSWORD_ENABLED') === 'true';
    if (!resetEnabled) {
      throw new ForbiddenException('Восстановление пароля временно недоступно');
    }

    try {
      // Проверяем валидность и срок токена из письма
      const payload = await this.jwtService.verifyAsync<{ sub: number }>(dto.token, {
        secret: this.configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET'),
      });

      // Находим пользователя по id из токена
      const user = await this.userService.findById(payload.sub);
      if (!user) {
        throw new NotFoundException('Пользователь не найден');
      }

      // Хэшируем новый пароль и обновляем у пользователя
      const hashedPassword = await argon2.hash(dto.newPassword);
      await this.userService.update(user.id, { password: hashedPassword });
    } catch (error) {
      // Если токен невалиден или истёк — возвращаем ошибку
      throw new BadRequestException('Неверный или истёкший токен сброса пароля');
    }
  }
}
