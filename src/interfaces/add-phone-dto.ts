import { ApiProperty } from "@nestjs/swagger";

export class AddPhoneDto {
    @ApiProperty({ example: '+00000000', description: 'phone number' })
    phoneNumber: string;
}