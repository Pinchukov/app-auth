import { IsInt, IsPositive, IsString, IsNotEmpty } from 'class-validator';

export class RefreshTokenDto {
  @IsInt()
  @IsPositive()
  userId: number;

  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}
