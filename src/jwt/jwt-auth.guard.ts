import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtAuthService } from './jwt.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwtAuthService: JwtAuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = request.headers['authorization']?.split(' ')[1];

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      const decoded = await this.jwtAuthService.verifyToken(token);
      request.user = decoded;
      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
