import * as mysql from 'mysql';
import { DatabaseAdapter } from './interfaces/database-adapter';
import { TokensDto } from './interfaces/tokens-dto';

export class MysqlAdapter implements DatabaseAdapter {
  private connection: mysql.Connection;

  constructor(private dbConfig: any) {
    this.connection = mysql.createConnection({
      host: dbConfig.host,
      user: dbConfig.username,
      password: dbConfig.password,
      database: dbConfig.database,
    });
    this.connection.connect();
  }

  async saveCredentials(CognitoUserId: string, credentials: TokensDto): Promise<void> {
    const query = `...`; // Implement the query
    // Implement the rest of the method
  }
	
	async updateCredentials(CognitoUserId: string, newCredentials: TokensDto): Promise<void> {
		throw new Error("Method not implemented.");
	}

	async getCredentials(CognitoUserId: string): Promise<TokensDto | null> {
		throw new Error("Method not implemented.");
	}

	async clearCredentials(CognitoUserId: string): Promise<void> {
		throw new Error("Method not implemented.");
	}

}
