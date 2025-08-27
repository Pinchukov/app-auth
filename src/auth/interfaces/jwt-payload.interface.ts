import { Role } from '@prisma/client';

export interface JwtPayload {
  sub: number;
  email: string;
  //name: string;
  role: Role;
  iat?: number;
  exp?: number;
}
