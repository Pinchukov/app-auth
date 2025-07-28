import {
  IsBoolean,
  IsOptional,
  IsString,
  MinLength,
  MaxLength,
} from 'class-validator';

export class UpdateNewsDto {
  @IsOptional()
  @IsString()
  @MinLength(3)
  @MaxLength(200)
  title?: string;

  @IsOptional()
  @IsString()
  @MinLength(10)
  text?: string;

  @IsOptional()
  @IsString()
  @MinLength(3)
  @MaxLength(100)
  url?: string;

  @IsOptional()
  @IsBoolean()
  status?: boolean;
}
