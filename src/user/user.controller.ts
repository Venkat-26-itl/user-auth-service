import { Controller, Post, Body, Headers, UseGuards, Get } from '@nestjs/common';
import { UserService } from './user.service';
import { SignupDto } from 'src/dtos/user-signup.dto';
import { LoginDto } from 'src/dtos/user-login.dto';
import { JwtAuthGuard } from 'src/jwt/jwt-auth.guard';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('signup')
  async signup(@Body() signupDto: SignupDto) {
    const { email, password, name, mobileNumber } = signupDto;
    await this.userService.signup(email, password, name, mobileNumber);
    return { message: 'Signup successful' };
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    const { email, password } = loginDto;
    const token = await this.userService.login(email, password);
    return { token };
  }

  @Get('getUserId')
  @UseGuards(JwtAuthGuard)
  async getUserIdFromToken(@Headers('authorization') authToken: string) {
    const token = authToken.startsWith('Bearer ')
      ? authToken.slice(7)
      : authToken;
    const userId = await this.userService.getUserIdFromToken(token);
    return { userId };
  }
}
