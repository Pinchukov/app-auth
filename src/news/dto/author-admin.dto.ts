import { Expose } from 'class-transformer';
import { Role } from '@prisma/client';

export class AuthorAdminDto {
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

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;
}
