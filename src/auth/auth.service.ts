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
export class AuthService {
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
    this.jwtAccessExpiry = this.configService.get<string>('JWT_ACCESS_TOKEN_EXPIRATION', '15m');
    this.jwtRefreshExpiry = this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRATION', '7d');
    this.jwtResetPwdExpiry = this.configService.get<string>('JWT_RESET_PASSWORD_EXPIRATION', '15m');
  }

  async getTokens(
    userId: number,
    email: string,
    role: Role,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, email, role },
        {
          secret: this.configService.get<string>('JWT_ACCESS_TOKEN_SECRET')?.replace(/^"(.+)"$/, '$1'),
          expiresIn: this.jwtAccessExpiry,
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, email, role },
        {
          secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET')?.replace(/^"(.+)"$/, '$1'),
          expiresIn: this.jwtRefreshExpiry,
        },
      ),
    ]);
    return { accessToken, refreshToken };
  }

  async updateRefreshToken(userId: number, refreshToken: string): Promise<void> {
    const hashed = await argon2.hash(refreshToken);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: hashed },
    });
  }

  async refreshTokens(
    userId: number,
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, role: true, refreshToken: true },
    });
    if (!user || !user.refreshToken) {
      throw new ForbiddenException('Доступ запрещён');
    }

    const isValid = await argon2.verify(user.refreshToken, refreshToken);
    if (!isValid) {
      throw new ForbiddenException('Доступ запрещён');
    }

    const tokens = await this.getTokens(user.id, user.email, user.role);
    await this.updateRefreshToken(user.id, tokens.refreshToken);
    return tokens;
  }

  async logout(userId: number): Promise<void> {
    if (!userId) {
      throw new BadRequestException('Для выхода из системы требуется идентификатор пользователя (userId).');
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

  async login(dto: LoginDto): Promise<{ accessToken: string; refreshToken: string }> {
    const loginEnabled = this.configService.get<string>('LOGIN_ENABLED') === 'true';
    if (!loginEnabled) {
      throw new ForbiddenException('Авторизация в данный момент недоступна');
    }

    const user = await this.prisma.user.findUnique({ where: { email: dto.email } });
    if (!user) {
      throw new UnauthorizedException('Неверный email или пароль');
    }

    const passwordMatches = await argon2.verify(user.password, dto.password);
    if (!passwordMatches) {
      throw new UnauthorizedException('Неверный email или пароль');
    }

    const emailVerificationEnabled = this.configService.get<string>('EMAIL_VERIFICATION_ENABLED') === 'true';
    if (emailVerificationEnabled && !user.status) {
      throw new ForbiddenException('Пользователь не активен');
    }

    const tokens = await this.getTokens(user.id, user.email, user.role);
    await this.updateRefreshToken(user.id, tokens.refreshToken);
    return tokens;
  }

  async register(dto: RegisterDto) {
    const registrationEnabled = this.configService.get<string>('REGISTRATION_ENABLED') === 'true';
    if (!registrationEnabled) {
      throw new ForbiddenException('Регистрация в данный момент недоступна');
    }

    const existingUser = await this.userService.findByEmail(dto.email);
    if (existingUser) {
      throw new ConflictException('Пользователь с таким email уже существует');
    }

    const emailVerificationEnabled = this.configService.get<string>('EMAIL_VERIFICATION_ENABLED') === 'true';

    const user = await this.userService.create({
      name: dto.name,
      email: dto.email,
      password: dto.password,
      status: !emailVerificationEnabled,
      role: Role.USER,
    });

    if (emailVerificationEnabled) {
      const token = await this.emailVerificationService.generateEmailVerificationToken(user.id, user.email);
      await this.emailVerificationService.sendVerificationEmail(user.email, token);
      return {
        message: 'Регистрация успешна! Пожалуйста, подтвердите email, перейдя по ссылке в письме.',
      };
    }

    const tokens = await this.getTokens(user.id, user.email, user.role);
    await this.updateRefreshToken(user.id, tokens.refreshToken);
    return {
      user: {
        id: user.id,
        //name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
      },
      tokens,
    };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const resetEnabled = this.configService.get<string>('RESET_PASSWORD_ENABLED') === 'true';
    if (!resetEnabled) {
      throw new ForbiddenException('Восстановление пароля временно недоступно');
    }

    const user = await this.userService.findByEmail(dto.email);
    if (!user) {
      return;
    }

    const token = await this.jwtService.signAsync(
      { sub: user.id },
      {
        secret: this.configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET')?.replace(/^"(.+)"$/, '$1'),
        expiresIn: this.jwtResetPwdExpiry,
      },
    );

    await this.emailVerificationService.sendResetPasswordEmail(user.email, token);
  }

  async resetPassword(dto: ResetPasswordDto) {
    const resetEnabled = this.configService.get<string>('RESET_PASSWORD_ENABLED') === 'true';
    if (!resetEnabled) {
      throw new ForbiddenException('Восстановление пароля временно недоступно');
    }

    try {
      const payload = await this.jwtService.verifyAsync<{ sub: number }>(dto.token, {
        secret: this.configService.get<string>('JWT_EMAIL_VERIFICATION_SECRET')?.replace(/^"(.+)"$/, '$1'),
      });

      const user = await this.userService.findById(payload.sub);
      if (!user) {
        throw new NotFoundException('Пользователь не найден');
      }

      const hashedPassword = await argon2.hash(dto.newPassword);
      await this.userService.update(user.id, { password: hashedPassword });
    } catch (error) {
      throw new BadRequestException('Неверный или истёкший токен сброса пароля');
    }
  }
}