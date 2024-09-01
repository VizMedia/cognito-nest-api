import { ApiProperty } from "@nestjs/swagger";

export class InitiatePasswordResetDto {
	@ApiProperty({ example: 'username', description: 'User email or phone number as username' })
	username: string;

	// @ApiProperty({ example: 'sms', description: 'User preferred verification method sms or email' })
	// prefferredMethod: string;
}
