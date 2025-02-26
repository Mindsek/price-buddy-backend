import { Logger } from '@nestjs/common';

const logger = new Logger('JwtConfig');

export const JWT_CONFIG = {
  secret:
    process.env.JWT_SECRET ||
    (() => {
      logger.warn(
        'JWT_SECRET not defined, using fallback secret - NOT SECURE FOR PRODUCTION',
      );
      return 'fallback_secret';
    })(),
  expiresIn: '30d',
};
