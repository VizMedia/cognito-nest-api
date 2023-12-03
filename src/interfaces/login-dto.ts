import { ApiProperty } from "@nestjs/swagger";

export class LoginDto {
	@ApiProperty({ example: 'user@example.com', description: 'User email or phone number' })
  emailOrPhone: string;

	@ApiProperty({ example: 'YourPassword123!', description: 'User password' })
  password: string;
}