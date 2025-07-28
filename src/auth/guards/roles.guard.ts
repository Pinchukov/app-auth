import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { ROLES_KEY } from './roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) { }

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Если роли не указаны — доступ открыт всем
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user || !user.role) {
      throw new ForbiddenException('Доступ запрещён: пользователь не авторизован');
    }

    // Уровень “ADMIN” имеет доступ ко всему
    if (user.role === Role.ADMIN) {
      return true;
    }

    // Проверяем, есть ли роль пользователя в списке разрешённых ролей
    if (!requiredRoles.includes(user.role)) {
      throw new ForbiddenException('Доступ запрещён: недостаточно прав');
    }

    return true;
  }
}
