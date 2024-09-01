import { Injectable, Inject } from '@nestjs/common';
import { DatabaseAdapter } from './interfaces/database-adapter';
import { MongoDbAdapter } from './db-adapter-mongodb';
import { MysqlAdapter } from './db-adapter-mysql';
import { TokensDto } from './interfaces/tokens-dto';
import { DatabaseConfig } from './interfaces/database-config';

@Injectable()
export class VizStorageService {
  private dbAdapter: DatabaseAdapter;

  constructor(@Inject('VIZ_DATABASE_CONFIG') private config: DatabaseConfig ) {
    if (config?.type === 'mongodb') {
      try {
        this.dbAdapter = new MongoDbAdapter(config);
      } catch (error) {
        console.error('Error connecting to MongoDB:');
      }
    } else if (config?.type === 'mysql') {
      try {
        this.dbAdapter = new MysqlAdapter(config);
      } catch (error) {
        console.error('Error connecting to MySQL:');
      }
    }
  }

  async saveCredentials(CognitoUserId: string, credentials: TokensDto): Promise<void> {
		
    await this.dbAdapter.saveCredentials(CognitoUserId, credentials);
  }

	async updateCredentials(CognitoUserId: string, newCredentials: TokensDto): Promise<void> {
		return await this.dbAdapter.updateCredentials(CognitoUserId, newCredentials);
	}

	async getCredentials(CognitoUserId: string): Promise<TokensDto | null> {
		return await this.dbAdapter.getCredentials(CognitoUserId);
	}

	async clearCredentials(CognitoUserId: string): Promise<void> {
		return await this.dbAdapter.clearCredentials(CognitoUserId);
	}

}
