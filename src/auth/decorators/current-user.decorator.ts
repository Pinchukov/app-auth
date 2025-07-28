import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

/**
 * Кастомный декоратор для удобного получения текущего аутентифицированного пользователя
 * из объекта запроса (request.user), который устанавливается в процессе аутентификации,
 * например, через JwtAuthGuard и JwtStrategy.
 * 
 * Использование:
 * В контроллере можно принять параметр с декоратором @CurrentUser(), чтобы получить
 * типизированный объект пользователя, не обращаясь напрямую к request.
 * 
 * Пример:
 *    @Get('profile')
 *    getProfile(@CurrentUser() user: JwtPayload) {
 *      return user;
 *    }
 * 
 * @param _data — необязательный параметр, который можно использовать для передачи данных в декоратор, здесь не используется
 * @param ctx — контекст выполнения (ExecutionContext), позволяет получить объект запроса и другие данные
 * @returns JwtPayload — текущий пользователь, извлечённый из request.user
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): JwtPayload => {
    // Получаем объект текущего HTTP-запроса из контекста
    const request = ctx.switchToHttp().getRequest();

    // Возвращаем объект пользователя, который был установлен в request.user в процессе аутентификации
    return request.user;
  },
);
