import { ApiProperty } from "@nestjs/swagger";

export class ConfirmRegistrationDto {
	@ApiProperty({ example: 'username', description: 'User username' })
	username: string;

	@ApiProperty({ example: 'code', description: 'User confirmation code' })
	code: string;
}
