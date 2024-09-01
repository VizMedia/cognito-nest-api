import { ApiProperty } from "@nestjs/swagger";

export class RegisterUserDto {
	@ApiProperty({ example: 'anyuser', description: 'User username' })
	username: string;

	@ApiProperty({ example: 'MyPassword#123', description: 'User password' })
	password: string;

	@ApiProperty({ example: 'anyuser@gmail.com', description: 'User email' })
	email: string;

	@ApiProperty({ example: '+000000000', description: 'User phone' })
	phone: string;

	@ApiProperty({ example: 'SMS', description: 'User preferred verification method SMS or EMAIL' })
	preferredMethod: string;
}