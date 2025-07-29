import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

// Определяем примитивные типы, которые могут входить в JSON
type Primitive = string | number | boolean | null;

// Универсальный тип для любых JSON-значений: примитив, объект или массив
type JsonValue = Primitive | JsonObject | JsonArray;

// Объект с произвольными ключами, где значения — JSON-значения
interface JsonObject {
  [key: string]: JsonValue;
}

// Массив JSON-значений
interface JsonArray extends Array<JsonValue> {}

// Интерфейс для структуры ответа, которую возвращает HttpException
export interface HttpExceptionResponse {
  statusCode?: number;           // HTTP статус код ошибки (например, 404)
  message?: string | string[];  // Сообщение или массив сообщений
  error?: string;                // Название ошибки (например, "Not Found")
  [key: string]: JsonValue | undefined; // Любые дополнительные поля
}

// Декоратор @Catch указывает, что фильтр обрабатывает HttpException
@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost) {
    // Получаем контекст запроса и ответа в HTTP среде
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    // Получаем статус код, например 400, 404, 500 и т.д.
    const status = exception.getStatus();

    // Получаем тело исключения — это может быть строка или объект с деталями
    const exceptionResponse = exception.getResponse();

    // Приводим к интерфейсу HttpExceptionResponse, если объект
    const responseObj: HttpExceptionResponse | null =
      typeof exceptionResponse === 'object' ? (exceptionResponse as HttpExceptionResponse) : null;

    // Определяем имя ошибки
    const error = responseObj?.error || exception.name;

    // Получаем сообщение или массив сообщений
    const messageRaw = responseObj?.message || exception.message;

    // Если сообщение массив - объединяем в строку через "; "
    const message = Array.isArray(messageRaw) ? messageRaw.join('; ') : messageRaw;

    // Логируем предупреждения для часто встречающихся клиентских ошибок
    if ([400, 401, 403, 404, 409, 429].includes(status)) {
      this.logger.warn(`HTTP Exception: [${status}] ${message} | Path: ${request.url}`);
    } else {
      // Все прочие ошибки логируем с уровнем error и стеком вызовов
      this.logger.error(
        `HTTP Exception: [${status}] ${message} | Path: ${request.url}`,
        exception.stack,
      );
    }

    // Возвращаем клиенту структурированный JSON с деталями ошибки
    response.status(status).json({
      statusCode: status,
      error,
      message,
      timestamp: new Date().toISOString(),
      path: request.url,
    });
  }
}
