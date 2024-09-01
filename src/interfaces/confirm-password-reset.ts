import { ApiProperty } from "@nestjs/swagger";

export class ConfirmPasswordResetDto {
	@ApiProperty({ example: 'user@example.com', description: 'User email or phone number into AWS Cognito' })
	username: string;

	@ApiProperty({ example: 'YourPassword123!', description: 'User new password' })
	newPassword: string;

	@ApiProperty({ example: '123456', description: 'Confirmation code sent to user email or phone number' })
	confirmationCode: string;
}