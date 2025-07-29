import { IsString, IsNotEmpty } from 'class-validator';

/**
 * DTO (Data Transfer Object) для параметров query-запроса при верификации email.
 * Используется для валидации входящих параметров запроса.
 */
export class VerifyEmailQueryDto {
  /**
   * Токен подтверждения email, передаваемый в query-параметре `token`.
   * 
   * Декораторы валидации:
   * - @IsString() — гарантирует, что значение является строкой.
   * - @IsNotEmpty() — гарантирует, что строка не пустая.
   */
  @IsString()
  @IsNotEmpty()
  token: string;
}
