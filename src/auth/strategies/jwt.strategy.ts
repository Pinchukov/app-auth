import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { ExtractJwt, Strategy, StrategyOptionsWithoutRequest } from 'passport-jwt';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { UserService } from '../../user/user.service';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) {
    super(JwtStrategy.getStrategyOptions(configService));
  }

  private static getStrategyOptions(configService: ConfigService): StrategyOptionsWithoutRequest {
    const secretRaw = configService.get<string>('JWT_ACCESS_TOKEN_SECRET');
    if (!secretRaw) {
      throw new Error('JWT_ACCESS_TOKEN_SECRET is not defined!');
    }

    const secret = secretRaw.replace(/^"(.+)"$/, '$1');

    return {
      jwtFromRequest: (req: Request) => {
        if (!req) return null;

        if (req.cookies && req.cookies['accessToken']) {
          return req.cookies['accessToken'];
        }

        return ExtractJwt.fromAuthHeaderAsBearerToken()(req);
      },
      secretOrKey: secret,
      ignoreExpiration: false,
      passReqToCallback: false,
    };
  }

  async validate(payload: JwtPayload): Promise<JwtPayload> {
    if (!payload.sub || !payload.email) {
      throw new UnauthorizedException(
        'Неверная полезная нагрузка токена: отсутствует userId или email',
      );
    }

    const user = await this.userService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('Пользователь не найден');
    }

    return {
      sub: user.id,
      email: user.email,
      role: user.role,
    };
  }
}
