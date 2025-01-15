import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { User } from '../models/user.model';
import * as bcrypt from 'bcrypt';
import * as CryptoJS from "crypto-js";
import { JwtAuthService } from 'src/jwt/jwt.service';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User)
    private readonly userModel: typeof User,
    private readonly jwtAuthService: JwtAuthService,
  ) {}

  async signup(email: string, password: string, name: string, mobileNumber: string) {
    const existingUser = await this.userModel.findOne({ where: { email } });
    if (existingUser) throw new UnauthorizedException('Email already in use');

    const hashedPassword = await bcrypt.hash(password, 10);
    await this.userModel.create({ email, password: hashedPassword, name, mobileNumber });
  }

  async login(email: string, encryptedPassword: string): Promise<{ accessToken: string }> {
    const decryptionKey: string = process.env.PASSWORD_ENCRYPTION_KEY;
    const decryptedBytes = CryptoJS.AES.decrypt(encryptedPassword, decryptionKey);
    const decryptedPassword: string = decryptedBytes.toString(CryptoJS.enc.Utf8);
  
    const user: User | null = await this.userModel.findOne({ where: { email } });
    if (!user) throw new UnauthorizedException("Invalid credentials");
  
    const isPasswordMatching: boolean = await bcrypt.compare(decryptedPassword, user.password);
    if (!isPasswordMatching) throw new UnauthorizedException("Invalid credentials");
  
    const payload = { id: user.id, email: user.email };
    const token = await this.jwtAuthService.signToken(payload);
  
    return { accessToken: token };
  }

  async getUserIdFromToken(token: string): Promise<number> {
    try {
      const decoded = await this.jwtAuthService.verifyToken(token);

      const user = await this.userModel.findByPk(decoded.id);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      return user.id;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}