import { Module } from '@nestjs/common';
import { SequelizeModule } from '@nestjs/sequelize';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { User } from '../models/user.model';
import { JwtAuthModule } from 'src/jwt/jwt-auth.module';

@Module({
  imports: [
    SequelizeModule.forFeature([User]),
    JwtAuthModule,
  ],
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule {}
