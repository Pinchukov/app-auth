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

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name);

  constructor(private reflector: Reflector) {}

  /**
   * Проверяет, имеет ли роль пользователя необходимые права.
   * Администратор (Role.ADMIN) имеет доступ ко всему.
   * @param userRole - роль пользователя
   * @param requiredRoles - роли, необходимые для доступа
   * @returns true, если доступ разрешён
   */
  private hasRole(userRole: Role, requiredRoles: Role[]): boolean {
    if (userRole === Role.ADMIN) {
      return true;
    }
    return requiredRoles.includes(userRole);
  }

  canActivate(context: ExecutionContext): boolean {
    // Получаем роли, требуемые для текущего обработчика или контроллера
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Если роли не указаны — доступ открыт всем
    if (!requiredRoles || requiredRoles.length === 0) {
      this.logger.debug('Отсутствуют роли — доступ открыт всем');
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    // Проверяем наличие авторизованного пользователя и его роли
    if (!user?.role) {
      this.logger.warn('Доступ запрещён: пользователь не авторизован или роль отсутствует');
      throw new ForbiddenException('Доступ запрещён: пользователь не авторизован');
    }

    // Проверяем, есть ли у пользователя требуемая роль
    if (this.hasRole(user.role, requiredRoles)) {
      return true;
    }

    this.logger.warn(`Доступ запрещён: недостаточно прав у пользователя с ролью "${user.role}"`);
    throw new ForbiddenException('Доступ запрещён: недостаточно прав');
  }
}
