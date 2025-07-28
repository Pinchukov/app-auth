import { Controller, Get, Query, ValidationPipe } from '@nestjs/common';
import { EmailVerificationService, VerifyEmailResponseDto } from './email-verification.service';
import { VerifyEmailQueryDto } from './dto/verify-email-query.dto';

@Controller('auth') // Декоратор, который задаёт базовый путь для всех маршрутов этого контроллера — /auth
export class EmailVerificationController {
  // Внедряем сервис для работы с верификацией email
  constructor(private readonly emailVerificationService: EmailVerificationService) { }

  /**
   * Обработчик HTTP GET запроса по пути /auth/verify
   * @param query - объект DTO с параметрами запроса, валидируется ValidationPipe
   * @returns Promise с результатом верификации email (сообщение о результате)
   */
  @Get('verify')
  async verifyEmail(
    @Query(new ValidationPipe()) query: VerifyEmailQueryDto, // Параметры запроса берутся из query и валидируются
  ): Promise<VerifyEmailResponseDto> {
    // Вызываем метод сервиса для проверки и верификации email по переданному токену
    return this.emailVerificationService.verifyEmailToken(query.token);
  }
}
