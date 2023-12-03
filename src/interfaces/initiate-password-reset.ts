import { ApiProperty } from "@nestjs/swagger";

export class InitiatePasswordResetDto {
	@ApiProperty({ example: 'example@mail.com', description: 'User email or phone number as username' })
	username: string;
}
