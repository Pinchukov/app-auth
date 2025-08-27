import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { ROLES_KEY } from './roles.decorator';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name);

  constructor(private reflector: Reflector) {}

  private hasRole(userRole: Role, requiredRoles: Role[]): boolean {
    if (userRole === Role.ADMIN) {
      return true;
    }
    return requiredRoles.includes(userRole);
  }

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true; // Публичный маршрут — пропускаем проверку ролей
    }

    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles || requiredRoles.length === 0) {
      this.logger.debug('Отсутствуют роли — доступ открыт всем');
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user?.role) {
      this.logger.warn('Доступ запрещён: пользователь не авторизован или роль отсутствует');
      throw new ForbiddenException('Доступ запрещён: пользователь не авторизован');
    }

    if (this.hasRole(user.role, requiredRoles)) {
      return true;
    }
    this.logger.warn(`Доступ запрещён: недостаточно прав у пользователя с ролью "${user.role}"`);
    throw new ForbiddenException('Доступ запрещён: недостаточно прав');
  }
}
