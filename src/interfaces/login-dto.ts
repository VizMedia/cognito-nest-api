import { ApiProperty } from "@nestjs/swagger";

export class LoginDto {
	@ApiProperty({ example: 'username', description: 'User, email or phone number' })
  username: string;
  //emailOrPhone: string;

	@ApiProperty({ example: 'YourPassword123!', description: 'User password' })
  password: string;
}