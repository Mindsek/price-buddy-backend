import {
  Body,
  Controller,
  Get,
  Logger,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { AuthBodyDto, AuthCreateUserDto, AuthResponse } from './dto/auth.dto';
import { JwtPayload } from './types/jwt-payload.type';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(private authService: AuthService) {}

  @Post('login')
  @ApiOperation({ summary: 'Login a user' })
  @ApiResponse({
    status: 200,
    description: 'Login successful, returns a JWT token',
    type: AuthResponse,
  })
  @ApiResponse({
    status: 404,
    description: 'User or password incorrect',
  })
  async login(@Body() authBody: AuthBodyDto, @Res() res: Response) {
    this.logger.log(
      `Login attempt for email: ${authBody.email} from IP: ${res.req.ip}`,
    );
    try {
      const { access_token } = await this.authService.login(authBody);

      res.cookie('auth-session', access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        path: '/',
      });

      this.logger.log(`Login successful for email: ${authBody.email}`);
      res.json({ message: 'Connection successful', access_token });
    } catch (error) {
      this.logger.error(
        `Login failed for email: ${authBody.email} - Error: ${error.message}`,
      );
      throw error;
    }
  }

  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({
    status: 200,
    description: 'Registration successful, returns a JWT token',
    type: AuthResponse,
  })
  @ApiResponse({
    status: 400,
    description: 'Email already in use',
  })
  @ApiResponse({
    status: 400,
    description: 'Username already taken',
  })
  async register(@Body() body: AuthCreateUserDto, @Res() res: Response) {
    this.logger.log(
      `Registration attempt for email: ${body.email}, username: ${body.username} from IP: ${res.req.ip}`,
    );
    try {
      const { access_token } = await this.authService.register(body);

      res.cookie('auth-session', access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        path: '/',
      });

      this.logger.log(
        `Registration successful for email: ${body.email}, username: ${body.username}`,
      );
      res.json({ message: 'Registration successful', access_token });
    } catch (error) {
      this.logger.error(
        `Registration failed for email: ${body.email}, username: ${body.username} - Error: ${error.message}`,
      );
      throw error;
    }
  }

  @Get('verify')
  @UseGuards(AuthGuard)
  @ApiOperation({ summary: 'Verify if the JWT token is valid' })
  @ApiResponse({
    status: 200,
    description: 'Token valid, returns user info',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        email: { type: 'string' },
        username: { type: 'string' },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Invalid or missing token' })
  verify(@Req() req: Request & { user: JwtPayload }, @Res() res: Response) {
    const user = req.user;

    this.logger.log(`Verification successful for user: ${user.username}`);
    res.json({
      id: user.id,
      email: user.email,
      username: user.username,
    });
  }
}
