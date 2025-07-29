import {
  Controller,
  Post,
  Body,
  Res,
  HttpStatus,
  Get,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { JwtService } from '@nestjs/jwt';

import { AuthService } from './auth.service';

import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RegisterDto } from './dto/register.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

import { RegisterRateLimitGuard } from '../security/guards/register-rate-limit.guard';
import { ForgotPasswordRateLimitGuard } from '../security/guards/forgot-password-rate-limit.guard';

import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { ConfigService } from '@nestjs/config';

@Controller('auth')
// Контроллер для маршрутов аутентификации и управления сессиями
export class AuthController {
  constructor(
    private readonly authService: AuthService,  // Сервис аутентификации
    private readonly jwtService: JwtService,    // Сервис для работы с JWT
    private readonly configService: ConfigService,  // Работа с конфигурацией приложения
  ) {}

  // Метод для парсинга строковых периодов (например, "15m", "7d") в миллисекунды для установки срока действия cookie
  private parseDurationToMs(duration?: string): number {
    if (!duration) return 0;
    const match = duration.match(/^(\d+)([smhd])$/); // Регулярка для извлечения числа и единицы времени
    if (!match) return 0;

    const value = parseInt(match[1], 10);

    // Переводим единицу в миллисекунды
    switch (match[2]) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: return 0;
    }
  }

  // Получить базовые опции для установки cookie из конфигурации приложения
  private getCookieOptions() {
    return {
      httpOnly: true, // Защищает cookie от доступа JavaScript (XSS)
      secure: this.configService.get<boolean>('COOKIE_SECURE', false), // Передавать ли cookie только по HTTPS
      sameSite: (this.configService.get<string>('COOKIE_SAME_SITE') as 'strict' | 'lax' | 'none') || 'strict', // Политика SameSite
      path: this.configService.get<string>('COOKIE_PATH', '/'), // Путь, для которого доступны cookie
    };
  }

  // Метод для установки cookie с access и refresh токенами в ответ клиенту
  private setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
    const cookieBaseOptions = this.getCookieOptions();

    // Вычисляем время жизни cookie на основе конфигурации JWT
    const accessTokenMaxAge = this.parseDurationToMs(this.configService.get<string>('JWT_ACCESS_TOKEN_EXPIRATION'));
    const refreshTokenMaxAge = this.parseDurationToMs(this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRATION'));

    // Устанавливаем cookie с токенами и соответствующими сроками
    res.cookie('accessToken', accessToken, { ...cookieBaseOptions, maxAge: accessTokenMaxAge });
    res.cookie('refreshToken', refreshToken, { ...cookieBaseOptions, maxAge: refreshTokenMaxAge });
  }

  // POST /auth/login - Авторизация пользователя
  @Post('login')
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    // Получаем пару токенов доступа и обновления из AuthService
    const tokens = await this.authService.login(dto);

    // Декодируем access токен, чтобы получить полезную нагрузку (payload)
    const payload = this.jwtService.decode(tokens.accessToken) as JwtPayload;

    // Устанавливаем токены в cookie клиенту
    this.setAuthCookies(res, tokens.accessToken, tokens.refreshToken);

    // Отправляем ответ с ролью пользователя и сообщением об успехе
    res.status(HttpStatus.CREATED).json({
      role: payload.role,
      message: 'Авторизация успешна',
    });
  }

  // GET /auth/session - Получение информации о текущей сессии пользователя
  @Get('session')
  getSession(@Req() req: Request) {
    const token = req.cookies['accessToken']; // Получаем access token из cookie
    if (!token) {
      throw new UnauthorizedException('Нет токена авторизации');
    }
    try {
      // Проверяем валидность токена и извлекаем payload
      const payload = this.jwtService.verify<JwtPayload>(token, {
        secret: this.configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
      });
      // Возвращаем данные пользователя из токена
      return {
        email: payload.email,
        role: payload.role,
        sub: payload.sub,
      };
    } catch {
      // В случае ошибки (невалидный или просроченный токен) выбрасываем исключение
      throw new UnauthorizedException('Недействительный токен');
    }
  }

  // POST /auth/refresh - Обновление токенов с помощью refresh токена
  @Post('refresh')
  async refresh(
    @Body() dto: RefreshTokenDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    // Вызываем сервис для получения новых токенов
    const tokens = await this.authService.refreshTokens(dto.userId, dto.refreshToken);

    // Устанавливаем новые токены в cookie
    this.setAuthCookies(res, tokens.accessToken, tokens.refreshToken);

    // Отправляем подтверждение обновления
    res.status(HttpStatus.OK).json({ message: 'Токены обновлены' });
  }

  // POST /auth/register - Регистрация нового пользователя с ограничением по скорости запросов
  @Post('register')
  @UseGuards(RegisterRateLimitGuard) // Защита от спама регистрации (rate limiting)
  async register(@Body() dto: RegisterDto, @Res({ passthrough: true }) res: Response) {
    // Вызывает сервис регистрации и получает результат, который может содержать токены или сообщение с подтверждением email
    const result = await this.authService.register(dto);

    // Если есть токены, устанавливаем их в cookie для пользователя
    if (result.tokens) {
      this.setAuthCookies(res, result.tokens.accessToken, result.tokens.refreshToken);
    }

    // Возвращаем результат (сообщение или данные пользователя)
    return result;
  }

  // POST /auth/logout - Выход пользователя из системы с проверкой JWT
  @Post('logout')
  @UseGuards(JwtAuthGuard) // Защита маршрута проверкой JWT access токена
  async logout(@CurrentUser() user: JwtPayload, @Res({ passthrough: true }) res: Response) {
    // Вызываем сервис для удаления refresh токена пользователя из базы
    await this.authService.logout(user.sub);

    // Очищаем cookie токенов на стороне клиента
    const path = this.configService.get<string>('COOKIE_PATH', '/');
    res.clearCookie('accessToken', { path });
    res.clearCookie('refreshToken', { path });

    // Возвращаем сообщение об успешном выходе
    return { message: 'Выход выполнен успешно' };
  }

  // POST /auth/forgot-password - Запрос на сброс пароля с ограничением по скорости запросов
  @Post('forgot-password')
  @UseGuards(ForgotPasswordRateLimitGuard) // Защита от частых запросов восстановления пароля
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    // Вызываем сервис для отправки письма с инструкцией по сбросу пароля
    await this.authService.forgotPassword(dto);

    // Всегда возвращаем нейтральное сообщение для защиты от утечки информации о существовании email
    return { message: 'Если аккаунт с таким email существует, ссылка для сброса пароля отправлена.' };
  }

  // POST /auth/reset-password - Сброс пароля по токену и новому паролю
  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    // Вызываем сервис для сброса и обновления пароля
    await this.authService.resetPassword(dto);

    // Возвращаем сообщение об успешном завершении операции
    return { message: 'Пароль успешно изменён' };
  }
}
