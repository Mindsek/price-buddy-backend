import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { JWT_CONFIG } from 'src/config/jwt-config';
import { JwtPayload } from './types/jwt-payload.type';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private logger: Logger,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<Request & { user: JwtPayload }>();
    const token = this.extractTokenFromHeader(request);
    this.logger.log('token', token);
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: JWT_CONFIG.secret,
      });
      request.user = payload;
    } catch (error) {
      console.error(error);
      throw new UnauthorizedException('Invalid token');
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    if (type === 'Bearer' && token) {
      this.logger.log('Token Found in Authorization header');
      return token;
    }

    const cookieToken = request.cookies['auth-session'];
    if (cookieToken) {
      this.logger.log('Token found in auth-session cookie');
      return cookieToken as string;
    }

    return undefined;
  }
}
