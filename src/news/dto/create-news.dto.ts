import { IsBoolean, IsInt, IsNotEmpty, IsOptional, IsString, MinLength, MaxLength } from 'class-validator';

export class CreateNewsDto {
  @IsNotEmpty({ message: 'Заголовок не может быть пустым' })
  @IsString({ message: 'Заголовок должен быть строкой' })
  @MinLength(3, { message: 'Заголовок должен быть не менее 3 символов' })
  @MaxLength(200, { message: 'Заголовок не может превышать 200 символов' })
  title: string;

  @IsNotEmpty({ message: 'Текст новости не может быть пустым' })
  @IsString({ message: 'Текст должен быть строкой' })
  @MinLength(10, { message: 'Текст должен быть не менее 10 символов' })
  text: string;

  @IsNotEmpty({ message: 'URL не может быть пустым' })
  @IsString({ message: 'URL должен быть строкой' })
  @MinLength(3, { message: 'URL должен быть не менее 3 символов' })
  @MaxLength(100, { message: 'URL не может превышать 100 символов' })
  url: string;

  @IsOptional()
  @IsBoolean({ message: 'Поле status должно быть true или false' })
  status?: boolean;

  @IsNotEmpty({ message: 'authorId обязателен' })
  @IsInt({ message: 'authorId должен быть целым числом' })
  authorId: number;
}