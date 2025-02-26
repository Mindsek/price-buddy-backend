// import { Injectable } from '@nestjs/common';

// @Injectable()
// export class AuthService {}

import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcrypt';
import { JWT_CONFIG } from 'src/config/jwt-config';
import { User } from 'src/users/entities/user.entity';
import { UsersService } from 'src/users/users.service';
import { CreateUserDto } from './dto/auth.dto';

export class AuthResponse {
  access_token: string;
}

export class AuthBodyDto {
  email: string;
  password: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly usersService: UsersService,
  ) {}

  async register(data: CreateUserDto): Promise<AuthResponse> {
    const existingUserEmail = await this.usersService.findByEmail(data.email);
    const existingUserUsername = await this.usersService.findByUsername(
      data.username,
    );
    if (existingUserEmail || existingUserUsername) {
      throw new BadRequestException('User already exists');
    }
    const hashedPassword = await hash(data.password, 10);
    const user = await this.usersService.create({
      email: data.email,
      username: data.username,
      password: hashedPassword,
    });
    return this.authenticateUser(user);
  }

  async login(authBody: AuthBodyDto): Promise<AuthResponse> {
    const { email, password } = authBody;

    const existingUser = await this.usersService.findByEmail(email);
    this.logger.log(
      `Checking user with email: ${email}, found: ${JSON.stringify(
        existingUser,
      )}`,
    );
    if (!existingUser) {
      throw new NotFoundException('User or password incorrect');
    }

    const isPasswordValid = await this.isPasswordValid(
      password,
      existingUser.password,
    );
    this.logger.log('isPasswordValid', isPasswordValid);
    if (!isPasswordValid) {
      throw new NotFoundException('User or password incorrect');
    }

    return this.authenticateUser(existingUser);
  }

  private async isPasswordValid(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    this.logger.log('password', password);
    this.logger.log('hashedPassword', hashedPassword);
    return await compare(password, hashedPassword);
  }

  private async authenticateUser(user: User): Promise<AuthResponse> {
    const payload = { id: user.id, email: user.email, username: user.username };
    const access_token = await this.jwtService.signAsync(payload);
    this.logger.log('access_token', access_token);
    return { access_token };
  }

  async verifyToken(token: string): Promise<any> {
    try {
      return await this.jwtService.verify(token, {
        secret: JWT_CONFIG.secret,
      });
    } catch (error) {
      this.logger.error('Error verifying token', error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
