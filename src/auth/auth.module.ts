import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaService } from '../prisma/prisma.service';
import { UserModule } from '../user/user.module';
import { EmailVerificationModule } from '../EmailVerificationModule/email-verification.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { SecurityModule } from '../security/security.module';

@Module({
  imports: [
    // Глобальный модуль конфигурации для доступа к переменным окружения во всех модулях
    ConfigModule.forRoot({ isGlobal: true }),

    // Модуль Passport с регистрацией стратегии по умолчанию - JWT
    PassportModule.register({ defaultStrategy: 'jwt' }),

    // Асинхронная регистрация JwtModule с динамическим получением настроек из env
    JwtModule.registerAsync({
      imports: [ConfigModule], // Для доступа к ConfigService
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
        signOptions: {
          // Время жизни токена берём из env с резервным значением '15m'
          expiresIn: configService.get<string>('JWT_ACCESS_TOKEN_EXPIRATION') || '15m',
        },
      }),
      inject: [ConfigService],
    }),
    UserModule,
    EmailVerificationModule,
    SecurityModule,
  ],
  providers: [
    AuthService,
    PrismaService,
    JwtStrategy,
  ],
  controllers: [AuthController],
  exports: [
    AuthService,
    JwtModule,
    PassportModule,
    JwtStrategy,
  ],
})
export class AuthModule { }
