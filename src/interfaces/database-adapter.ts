import { TokensDto } from './tokens-dto';

export interface DatabaseAdapter {
  saveCredentials(CognitoUserId: string, credentials: TokensDto): Promise<void>;
  updateCredentials(CognitoUserId: string, newCredentials: TokensDto): Promise<void>;
  getCredentials(CognitoUserId: string): Promise<TokensDto | null>;
	clearCredentials(CognitoUserId: string): Promise<void>;
}
