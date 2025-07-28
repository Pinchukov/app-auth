import { Exclude, Expose } from 'class-transformer';
import { Role } from '@prisma/client';

export class UserDto {
  @Expose()
  id: number;

  @Expose()
  name: string;

  @Expose()
  email: string;

  @Expose()
  role: Role;

  @Expose()
  status: boolean;

  @Exclude()
  password: string;

  @Exclude()
  refreshToken: string | null;

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;
}
