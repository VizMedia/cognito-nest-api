import { ApiProperty } from "@nestjs/swagger";

export class UsernameDto {

    @ApiProperty({ description: 'Username' })
    username: string;
}