import {
  IsNotEmpty,
  IsString,
  MinLength,
  IsBoolean,
  IsOptional,
  IsEnum,
  IsEmail,
} from 'class-validator';
import { Role } from '@prisma/client';

export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  name: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(7)
  @IsEmail({}, { message: 'Некорректный email адрес' })
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(6, { message: 'Пароль должен быть не менее 6 символов' })
  password: string;

  @IsEnum(Role, {
    message: `Роль должна быть одной из: ${Object.values(Role).join(', ')}`,
  })
  @IsOptional()
  role?: Role;

  @IsBoolean()
  @IsOptional()
  status?: boolean;
}
