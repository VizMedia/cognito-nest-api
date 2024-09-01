import { ApiProperty } from "@nestjs/swagger";

export class AddEmailDto {
    @ApiProperty({ example: 'user@email.com', description: 'add user email to verify' })
    email: string;
}