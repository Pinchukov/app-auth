import {
  Controller,
  Post,
  Body,
  Res,
  //HttpStatus,
  Get,
  Req,
  UnauthorizedException,
  UseGuards,
  BadRequestException,
  //ForbiddenException,
  //ConflictException,
  //NotFoundException,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { JwtService } from '@nestjs/jwt';

import { AuthService } from './auth.service';

import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { RegisterDto } from './dto/register.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ValidateResetPasswordTokenDto } from './dto/validate-reset-password-token.dto';

import { RegisterRateLimitGuard } from '../security/guards/register-rate-limit.guard';
import { ForgotPasswordRateLimitGuard } from '../security/guards/forgot-password-rate-limit.guard';

import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { ConfigService } from '@nestjs/config';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  private parseDurationToMs(duration?: string): number {
    if (!duration) return 0;
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) return 0;
    const value = parseInt(match[1], 10);
    switch (match[2]) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: return 0;
    }
  }

  private getCookieOptions() {
    return {
      httpOnly: true,
      secure: this.configService.get<boolean>('COOKIE_SECURE', false),
      sameSite: (this.configService.get<string>('COOKIE_SAME_SITE') as 'strict' | 'lax' | 'none') || 'strict',
      path: this.configService.get<string>('COOKIE_PATH', '/'),
    };
  }

  private setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
    const cookieBaseOptions = this.getCookieOptions();

    const accessTokenMaxAge = this.parseDurationToMs(this.configService.get<string>('JWT_ACCESS_TOKEN_EXPIRATION'));
    const refreshTokenMaxAge = this.parseDurationToMs(this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRATION'));

    res.cookie('accessToken', accessToken, { ...cookieBaseOptions, maxAge: accessTokenMaxAge });
    res.cookie('refreshToken', refreshToken, { ...cookieBaseOptions, maxAge: refreshTokenMaxAge });
  }

  @Post('login')
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    const tokens = await this.authService.login(dto);

    // Раскодируем access токен, чтобы получить payload с email, name и role
    const payload = this.jwtService.decode(tokens.accessToken) as JwtPayload;

    this.setAuthCookies(res, tokens.accessToken, tokens.refreshToken);

    return {
      email: payload.email,
      //name: payload.name,
      role: payload.role,
      message: 'Авторизация успешна',
    };
  }

  @Get('session')
  getSession(@Req() req: Request) {
    const token = req.cookies['accessToken'];
    if (!token) {
      throw new UnauthorizedException('Нет токена авторизации');
    }
    try {
      const payload = this.jwtService.verify<JwtPayload>(token, {
        secret: this.configService.get<string>('JWT_ACCESS_TOKEN_SECRET')?.replace(/^"(.+)"$/, '$1'),
      });
      return {
        email: payload.email,
        //name: payload.name,
        role: payload.role,
        sub: payload.sub,
      };
    } catch {
      throw new UnauthorizedException('Недействительный токен');
    }
  }

  @Post('refresh')
  async refresh(
    @Body() dto: RefreshTokenDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.authService.refreshTokens(dto.userId, dto.refreshToken);

    this.setAuthCookies(res, tokens.accessToken, tokens.refreshToken);
    return { message: 'Токены обновлены' };
  }

  @Post('register')
  @UseGuards(RegisterRateLimitGuard)
  async register(@Body() dto: RegisterDto, @Res({ passthrough: true }) res: Response) {
    const result = await this.authService.register(dto);
    if (result.tokens) {
      this.setAuthCookies(res, result.tokens.accessToken, result.tokens.refreshToken);
    }
    return result;
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(@CurrentUser() user: JwtPayload, @Res({ passthrough: true }) res: Response) {
    await this.authService.logout(user.sub);

    const path = this.configService.get<string>('COOKIE_PATH', '/');
    res.clearCookie('accessToken', { path });
    res.clearCookie('refreshToken', { path });

    return { message: 'Выход выполнен успешно' };
  }

  @Post('forgot-password')
  @UseGuards(ForgotPasswordRateLimitGuard)
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    await this.authService.forgotPassword(dto);
    return { message: 'Если аккаунт с таким email существует, ссылка для сброса пароля отправлена.' };
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    await this.authService.resetPassword(dto);
    return { message: 'Пароль успешно изменён' };
  }

  @Post('validate-reset-password-token')
  async validateResetPasswordToken(@Body() dto: ValidateResetPasswordTokenDto) {
    try {
      await this.jwtService.verifyAsync(dto.token, {
        secret: this.configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET')?.replace(/^"(.+)"$/, '$1'),
      });
      return { message: 'Токен валиден' };
    } catch {
      throw new BadRequestException('Неверный или истёкший токен сброса пароля');
    }
  }
}
