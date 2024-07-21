import { MongoClient } from 'mongodb';
import { DatabaseAdapter } from './interfaces/database-adapter';
import { TokensDto } from './interfaces/tokens-dto';

export class MongoDbAdapter implements DatabaseAdapter {
  private client: MongoClient;

  constructor(private dbConfig: any) {
    // this.client = new MongoClient(`mongodb://${dbConfig.host}:${dbConfig.port}`, {
    //   auth: {
    //     username: dbConfig.username,
    //     password: dbConfig.password,
    //   },
    // });	

	let connectstring = `mongodb://${dbConfig.username}:${dbConfig.password}@${dbConfig.host}:${dbConfig.port}`;
	this.client = new MongoClient(connectstring);
    this.client.connect();
  }

  async saveCredentials(CognitoUserId: string, credentials: TokensDto): Promise<void> {
    const db = this.client.db(this.dbConfig.database);
    await db.collection('users').updateOne({ CognitoUserId }, { $set: credentials }, { upsert: true });
  }

	async updateCredentials(CognitoUserId: string, newCredentials: TokensDto): Promise<void> {
		return this.saveCredentials(CognitoUserId, newCredentials);
	}

	async getCredentials(CognitoUserId: string): Promise<TokensDto | null> {
		const db = this.client.db(this.dbConfig.database);
		let token = await db.collection('users').findOne({ CognitoUserId })

		if (!token) {
			return null;
		}
		
		let tokens: TokensDto = {
			accessToken: token.accessToken,
			idToken: token.idToken,
			refreshToken: token.refreshToken,
		};

		return tokens;
	}

	async clearCredentials(CognitoUserId: string): Promise<void> {
		const db = this.client.db(this.dbConfig.database);
		await db.collection('users').deleteOne({ CognitoUserId });
	}

}
