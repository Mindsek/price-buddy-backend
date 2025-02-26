export type JwtPayload = {
  id: string;
  email: string;
  username: string;
  iat?: number;
  exp?: number;
};
