import { MongoClient } from 'mongodb';
import { DatabaseAdapter } from './interfaces/database-adapter';
import { TokensDto } from './interfaces/tokens-dto';

export class MongoDbAdapter implements DatabaseAdapter {
	private client: MongoClient;

	constructor(private dbConfig: any) {
		this.connectToDb();
	}

	private async connectToDb() {
		try {
		  const connectstring = `mongodb://${this.dbConfig.username}:${this.dbConfig.password}@${this.dbConfig.host}:${this.dbConfig.port}`;
		  this.client = new MongoClient(connectstring);
		  await this.client.connect();  // Asynchroniczne połączenie z MongoDB
		  console.log('Successfully connected to MongoDB');
		} catch (error) {
		  console.error('Error connecting to MongoDB:', error.message);  // Skrócony komunikat błędu
		}
	  }


	async saveCredentials(CognitoUserId: string, credentials: TokensDto): Promise<void> {
		try {
			const db = this.client.db(this.dbConfig.database);
			await db.collection('users').updateOne({ CognitoUserId }, { $set: credentials }, { upsert: true });
		} catch (error) {
			console.error('Error saving credentials:');
			//throw new Error('Failed to save credentials');
		}
	}

	async updateCredentials(CognitoUserId: string, newCredentials: TokensDto): Promise<void> {
		try {
			console.log(CognitoUserId, 'updateCredentials');
			return this.saveCredentials(CognitoUserId, newCredentials);
		} catch (error) {
			console.error('Error updating credentials:');
			//throw new Error('Failed to update credentials');
		}
	}

	async getCredentials(CognitoUserId: string): Promise<TokensDto | null> {
		try {
			const db = this.client.db(this.dbConfig.database);
			let token = await db.collection('users').findOne({ CognitoUserId });

			if (!token) {
				return null;
			}

			let tokens: TokensDto = {
				accessToken: token.accessToken,
				idToken: token.idToken,
				refreshToken: token.refreshToken,
			};

			return tokens;
		} catch (error) {
			console.error('Error retrieving credentials:');
			//throw new Error('Failed to retrieve credentials');
		}
	}

	async clearCredentials(CognitoUserId: string): Promise<void> {
		try {
			const db = this.client.db(this.dbConfig.database);
			await db.collection('users').deleteOne({ CognitoUserId });
		} catch (error) {
			console.error('Error clearing credentials:');
			//throw new Error('Failed to clear credentials');
		}
	}

}
