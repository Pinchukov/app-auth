export interface JwtPayload {
  userId: number;
  email?: string;
  sub?: number;
  iat?: number;
  exp?: number;
}
