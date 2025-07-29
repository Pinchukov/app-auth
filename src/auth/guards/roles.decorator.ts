import { SetMetadata } from '@nestjs/common';
import { Role } from '@prisma/client';

/**
 * Ключ метаданных, под которым будут сохраняться роли.
 * Используется для чтения метаданных в guard'ах (например, в RolesGuard).
 */
export const ROLES_KEY = 'roles';

/**
 * Декоратор для указания, какие роли необходимы для доступа
 * к определённому контроллеру или маршруту.
 *
 * @param roles - список допустимых ролей из enum `Role`
 * @returns Декоратор, который устанавливает метаданные с ключом `ROLES_KEY`
 * и значением — массива ролей.
 *
 * Пример использования:
 * ```
 * @Roles(Role.ADMIN, Role.MODERATOR)
 * @Get('some-protected-route')
 * ```
 */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
