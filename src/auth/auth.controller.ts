import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { RegisterDto } from './dto/register.dto';
import { RegisterRateLimitGuard } from '../security/guards/register-rate-limit.guard';
import { ForgotPasswordRateLimitGuard } from '../security/guards/forgot-password-rate-limit.guard';

@Controller('auth')
export class AuthController {
  // Внедрение сервиса аутентификации для обработки бизнес-логики
  constructor(private readonly authService: AuthService) { }

  @Post('refresh')
  async refresh(@Body() dto: RefreshTokenDto) {
    const { userId, refreshToken } = dto;
    return this.authService.refreshTokens(userId, refreshToken);
  }

  @Post('register')
  @UseGuards(RegisterRateLimitGuard) // Ограничение количества регистраций с одного IP
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  async login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard) // Защищённый маршрут — только авторизованные пользователи
  async logout(@CurrentUser() user: JwtPayload) {
    const userId = user.userId;
    await this.authService.logout(userId);
    return { message: 'Выход выполнен успешно' };
  }

  @Post('forgot-password')
  @UseGuards(ForgotPasswordRateLimitGuard) // Rate limit для запросов на сброс пароля с одного IP
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    await this.authService.forgotPassword(dto);
    return { message: 'Если аккаунт с таким email существует, ссылка для сброса пароля отправлена.' };
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    await this.authService.resetPassword(dto);
    return { message: 'Пароль успешно изменён' };
  }
}
