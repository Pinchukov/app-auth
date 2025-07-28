import { IsString, IsNotEmpty } from 'class-validator';

/**
 * DTO (Data Transfer Object) для параметров query-запроса при верификации email.
 * Используется для валидации параметров входящего запроса.
 */
export class VerifyEmailQueryDto {
  /**
   * Токен подтверждения email, передаваемый в query-параметре `token`.
   * 
   * Декораторы из class-validator обеспечивают, что:
   * - Значение должно быть строкой (@IsString)
   * - Значение не должно быть пустым (@IsNotEmpty)
   */
  @IsString()
  @IsNotEmpty()
  token: string;
}
