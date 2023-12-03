import { ApiProperty } from "@nestjs/swagger";

export class RegisterUserDto {
	@ApiProperty({ example: 'username', description: 'User username' })
	username: string;

	@ApiProperty({ example: 'password', description: 'User password' })
	password: string;

	@ApiProperty({ example: 'email', description: 'User email' })
	email: string;

	@ApiProperty({ example: 'phone', description: 'User phone' })
	phone: string;
}