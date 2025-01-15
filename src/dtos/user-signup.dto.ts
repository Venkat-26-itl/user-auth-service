import { IsEmail, IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';

export class SignupDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @Matches(/^\d{10}$/, { message: 'Mobile number must be 10 digits' })
  mobileNumber: string;

  @IsNotEmpty()
  @MinLength(6)
  password: string;
}