import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * Защитный guard для аутентификации с использованием JWT.
 * 
 * Наследуется от базового `AuthGuard` из `@nestjs/passport` с указанием стратегии 'jwt'.
 * 
 * Этот guard:
 * - Автоматически проверяет наличие и валидность JWT в заголовке запроса Authorization Bearer.
 * - При отсутствии или некорректности токена возвращает ошибку 401 Unauthorized.
 * - Позволяет защитить маршруты, требующие аутентификации.
 * 
 * Использование:
 * ```
 * @UseGuards(JwtAuthGuard)
 * @Get('protected')
 * async protectedRoute() {
 *   return { message: 'Доступ разрешён' };
 * }
 * ```
 * 
 * Благодаря наследованию и декоратору `@Injectable()`, guard может быть внедрён зависимостями NestJS.
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
