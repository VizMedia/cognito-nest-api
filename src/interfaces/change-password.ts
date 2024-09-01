import { ApiProperty } from "@nestjs/swagger";

export class ChangePasswordDto {
	@ApiProperty({ example: 'oldPassword', description: 'User old password' })
	oldPassword: string;

	@ApiProperty({ example: 'newPassword', description: 'User new password' })
	newPassword: string;
}