import { ApiProperty } from "@nestjs/swagger";

export class LoginSessionDto {
    @ApiProperty({ description: 'from returned obiect from signin' })
    medium: string;
    // CODE_DELIVERY_DELIVERY_MEDIUM: string;

    @ApiProperty({ description: 'from returned obiect from signin' })
    session: string;

    @ApiProperty({ description: 'from returned obiect from signin' })
    // USER_ID_FOR_SRP: string;
    username: string;

    @ApiProperty({ example: '123123!', description: 'MFA Code from eq: SMA' })
    mfacode: string;
}