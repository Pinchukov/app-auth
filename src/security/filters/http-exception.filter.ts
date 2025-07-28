import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
} from '@nestjs/common';

@Catch(HttpException)
// Декоратор @Catch указывает, что этот фильтр ловит исключения типа HttpException
export class HttpExceptionFilter implements ExceptionFilter {
  /**
   * Метод, вызываемый при перехвате исключения
   * @param exception - пойманное исключение типа HttpException
   * @param host - объект, предоставляющий доступ к контексту выполнения (запрос, ответ и т.д.)
   */
  catch(exception: HttpException, host: ArgumentsHost) {
    // Получаем контекст HTTP-запроса
    const ctx = host.switchToHttp();

    // Получаем объект ответа (response) Express/HTTP
    const response = ctx.getResponse();

    // Получаем объект запроса (request)
    const request = ctx.getRequest();

    // Получаем HTTP-статус исключения (например, 404, 400, 500)
    const status = exception.getStatus();

    // Получаем тело ответа из исключения — может быть строкой или объектом
    const exceptionResponse = exception.getResponse();

    // Извлекаем сообщение ошибки:
    // если тело — строка, используем её,
    // если объект — пытаемся взять поле message,
    // иначе используем стандартное сообщение исключения
    const message =
      typeof exceptionResponse === 'string'
        ? exceptionResponse
        : (exceptionResponse as any).message || exception.message;

    // Формируем и отправляем JSON-ответ клиенту с информацией об ошибке
    response.status(status).json({
      statusCode: status,               // HTTP статус ошибки
      message,                         // Сообщение об ошибке
      timestamp: new Date().toISOString(), // Время возникновения ошибки в ISO формате
      path: request.url,               // URL запроса, на котором возникла ошибка
    });
  }
}
