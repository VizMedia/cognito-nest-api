import { ApiProperty } from "@nestjs/swagger";

export class ConfirmPropertyDto {
	@ApiProperty({ example: 'code', description: 'User confirmation code' })
	code: string;

	@ApiProperty({ example: 'phone_number', description: 'email or phone_number' })
	attributeName: string;
}
