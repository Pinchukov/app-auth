import { IsString, IsNotEmpty } from 'class-validator';

export class ValidateResetPasswordTokenDto {
  @IsString()
  @IsNotEmpty()
  token: string;
}
