import {
  IsEmail,
  IsString,
  MinLength,
  IsNotEmpty,
  Validate,
  ValidationArguments,
  ValidatorConstraint,
  ValidatorConstraintInterface
} from 'class-validator';

@ValidatorConstraint({ name: 'MatchPasswords', async: false })
export class MatchPasswords implements ValidatorConstraintInterface {

  validate(value: any, args: ValidationArguments) {
    // Получаем имя связанного свойства (в нашем случае 'password')
    const [relatedPropertyName] = args.constraints;
    // Достаём значение связанного свойства из объекта DTO
    const relatedValue = (args.object as any)[relatedPropertyName];

    // Проверяем, что оба значения совпадают
    return value === relatedValue;
  }

  defaultMessage(args: ValidationArguments) {
    return 'Пароли не совпадают';
  }
}

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @MinLength(6)
  @IsNotEmpty()
  password: string;

  @IsString()
  @MinLength(6)
  @IsNotEmpty()
  @Validate(MatchPasswords, ['password'])
  passwordConfirm: string;
}
