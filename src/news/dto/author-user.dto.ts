import { Expose } from 'class-transformer';

export class AuthorUserDto {
  @Expose()
  name: string;

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;
}
