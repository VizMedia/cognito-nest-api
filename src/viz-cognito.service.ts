import { Injectable, Inject } from '@nestjs/common';
import { VizCognitoConfig } from './interfaces/viz-cognito-config.interface';
import { CognitoIdentityClient, GetIdCommand } from '@aws-sdk/client-cognito-identity';
import {
	ChangePasswordCommand,
	CognitoIdentityProviderClient,
	ConfirmForgotPasswordCommand,
	ConfirmSignUpCommand,
	ForgotPasswordCommand,
	GetUserCommand,
	GlobalSignOutCommand,
	InitiateAuthCommand,
	RespondToAuthChallengeCommand,
	SignUpCommand,
	SetUserPoolMfaConfigCommand,
	AdminSetUserMFAPreferenceCommand
} from '@aws-sdk/client-cognito-identity-provider';
import { createHmac } from 'crypto';
import jwksClient from 'jwks-rsa';
import * as jwt from 'jsonwebtoken';
import { VizStorageService } from './viz-storage.service';
import { TokensDto } from './interfaces/tokens-dto';
import { decode } from 'jsonwebtoken';
import { LoginSessionDto } from './interfaces/login-session';

@Injectable()
export class VizCognitoService {

	// private client: CognitoIdentityClient;
	private client: CognitoIdentityProviderClient;
	jwksClient: any;

	constructor(
		@Inject('VIZ_COGNITO_CONFIG') private readonly config: VizCognitoConfig,
		private readonly storageService: VizStorageService,
	) {
		// this.client = new CognitoIdentityClient({ region: this.config.region });   
		console.log('config', { ...this.config, dbConfig: { ...config.dbConfig, password: '***' }, clientSecret: '***' });
		this.client = new CognitoIdentityProviderClient({ region: this.config.region });
		this.jwksClient = jwksClient({
			jwksUri: `https://cognito-idp.${this.config.region}.amazonaws.com/${this.config.userPoolId}/.well-known/jwks.json`
		});

	}

	/**
	 * Rejestracja użytkownika
	 * https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/cognito-identity-provider/command/SignUpCommand/
	 * @param username 
	 * @param password 
	 * @param email 
	 * @param phone 
	 * @returns 
	 */
	async registerUser(username: string, password: string, email: string, phone: string): Promise<any> {
		const attributes = [];
		if (email) {
			attributes.push({ Name: 'email', Value: email });
		}
		if (phone) {
			attributes.push({ Name: 'phone_number', Value: phone });
		}

		const secretHash = this.calculateSecretHash(username);

		const command = new SignUpCommand({
			ClientId: this.config.clientId,
			SecretHash: secretHash,
			Username: username,
			Password: password,
			UserAttributes: attributes,
		});

		try {
			const response = await this.client.send(command);
			return response;
		} catch (error) {
			console.log('regiesterUser Error:', error);
			throw new Error(error.message);
		}
	}

	async confirmUserRegistration(username: string, code: string): Promise<any> {

		const secretHash = this.calculateSecretHash(username);

		const command = new ConfirmSignUpCommand({
			ClientId: this.config.clientId,
			SecretHash: secretHash,
			Username: username,
			ConfirmationCode: code,
		});

		try {
			const response = await this.client.send(command);
			return response;
		} catch (error) {
			throw new Error(error.message);
		}
	}

	async signIn(username: string, password: string): Promise<any> {

		const secretHash = this.calculateSecretHash(username);

		console.log('secretHash', secretHash);

		const command = new InitiateAuthCommand({
			AuthFlow: 'USER_PASSWORD_AUTH',
			ClientId: this.config.clientId,
			AuthParameters: {
				USERNAME: username,
				PASSWORD: password,
				SECRET_HASH: secretHash,
			},
		});

		try {

			// wysyłam polecenie logowania
			const response = await this.client.send(command);

			// Jeśli odpowiedź zawiera ChallengeName, oznacza to, że wymagana jest dodatkowa weryfikacja
			if (response.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
				// Obsłuż scenariusz wymagający zmiany hasła
				return {
					challengeName: 'NEW_PASSWORD_REQUIRED',
					session: response.Session,
					userAttributes: JSON.parse(response.ChallengeParameters.userAttributes),
				};
			}

			if (response.ChallengeName === 'SMS_MFA') {
				console.log('wymagany SMS_MFA');
				return response;
			}

			if (response.ChallengeName === 'SOFTWARE_TOKEN_MFA') {
				console.log('wymagany SOFTWARE_TOKEN_MFA');
				return response;
			}


			// sign in with no MFA

			const decodedToken = decode(response.AuthenticationResult?.IdToken) as any;
			let CognitoUserId: string = decodedToken ? decodedToken.sub : ''; // 'sub' to standardowy claim JWT zawierający identyfikator użytkownika

			let tokens: TokensDto = {
				accessToken: response.AuthenticationResult?.AccessToken,
				idToken: response.AuthenticationResult?.IdToken,
				refreshToken: response.AuthenticationResult?.RefreshToken,
			};

			await this.storageService.saveCredentials(CognitoUserId, tokens);

			return {
				IdToken: response.AuthenticationResult?.IdToken,
			};
		} catch (error) {
			throw new Error(error.message);
		}
	}

	async enableMFA_SMS(username: string, CognitoUserId: string): Promise<any> {
		try {
			const command = new AdminSetUserMFAPreferenceCommand({
				UserPoolId: this.config.userPoolId,
				Username: username,
				SMSMfaSettings: {
					Enabled: true,
					PreferredMfa: true
				},
				SoftwareTokenMfaSettings: {
					Enabled: false,
					PreferredMfa: false
				}
			});

			const response = await this.client.send(command);
			return response;
		} catch (error) {
			console.error('Error enabling MFA:', error);
			throw new Error(username + ' Error enabling MFA');
		}
	}

	async disableMFA(username: string, CognitoUserId: string): Promise<any> {
		try {
			const command = new AdminSetUserMFAPreferenceCommand({
				UserPoolId: this.config.userPoolId,
				Username: username,
				SMSMfaSettings: {
					Enabled: false,
					PreferredMfa: false
				},
				SoftwareTokenMfaSettings: {
					Enabled: false,
					PreferredMfa: false
				}
			});

			const response = await this.client.send(command);
			return response;
		} catch (error) {
			console.error('Error enabling MFA:', error);
			throw new Error(username + ' Error enabling MFA');
		}
	}

	async signInSession(loginSession: LoginSessionDto): Promise<any> { // response: any, mfaCode: string, challengeName: string): Promise<any> {

		const secretHash = this.calculateSecretHash(loginSession.USER_ID_FOR_SRP);

		let challengeName: string = '';
		let challengeNameCode: string = '';
		switch (loginSession?.CODE_DELIVERY_DELIVERY_MEDIUM) {
			case 'SMS':
				challengeName = 'SMS_MFA';
				challengeNameCode = 'SMS_MFA_CODE';
				break;
			case 'SOFTWARE_TOKEN':
				challengeName = 'SOFTWARE_TOKEN_MFA';
				challengeNameCode = 'SOFTWARE_TOKEN_MFA_CODE';
				break;
			default:
				challengeName = '';
				challengeNameCode = '';
				break;
		}

		console.log('challengeName', challengeName, loginSession.mfaCode);

		let command = new RespondToAuthChallengeCommand({
			ClientId: this.config.clientId,
			ChallengeName: challengeName,
			Session: loginSession.Session,			
			ChallengeResponses: {
				[challengeNameCode]: loginSession.mfaCode,
				USERNAME: loginSession.USER_ID_FOR_SRP,
				SECRET_HASH: secretHash,
			},
		});

		try {
			const response = await this.client.send(command);

			const decodedToken = decode(response.AuthenticationResult?.IdToken) as any;
			let CognitoUserId: string = decodedToken ? decodedToken.sub : ''; // 'sub' to standardowy claim JWT zawierający identyfikator użytkownika

			let tokens: TokensDto = {
				accessToken: response.AuthenticationResult?.AccessToken,
				idToken: response.AuthenticationResult?.IdToken,
				refreshToken: response.AuthenticationResult?.RefreshToken,
			};

			await this.storageService.saveCredentials(CognitoUserId, tokens);

			return {
				IdToken: response.AuthenticationResult?.IdToken,
			};

		} catch (error) {
			console.log('error respondToMFAChallenge', error.message);
			throw new Error(error.message);
		}
	}


	async signOut(CognitoUserId: string): Promise<any> {
		// Pobranie accessToken z VizStorageService
		const currentTokens = await this.storageService.getCredentials(CognitoUserId);

		if (!currentTokens || !currentTokens.accessToken) {
			throw new Error('Brak accessToken, nie można wylogować użytkownika');
		}

		const command = new GlobalSignOutCommand({
			AccessToken: currentTokens.accessToken
		});

		try {
			const response = await this.client.send(command);
			await this.storageService.clearCredentials(CognitoUserId);
			return response; // Zwraca informacje o statusie wylogowania
		} catch (error) {
			throw new Error(error.message);
		}
	}

	private calculateSecretHash(username: string): string {
			const secretHash = createHmac('sha256', this.config.clientSecret) // Użyj Twojego client secret
				.update(username + this.config.clientId)
				.digest('base64');
			return secretHash;
	}

	async verifyToken(token: string): Promise<any> {
		if (!token) {
			throw new Error('Token is required');
		}

		// Dekoduj token, aby uzyskać identyfikator klucza (kid)
		const decodedToken = jwt.decode(token, { complete: true });
		const kid = decodedToken?.header.kid;

		// Pobierz klucz publiczny
		const key = await this.jwksClient.getSigningKey(kid);
		const publicKey = key.getPublicKey();

		// Weryfikuj token
		try {
			const verifiedToken = jwt.verify(token, publicKey, {
				algorithms: ['RS256'],
				audience: this.config.clientId,
				issuer: `https://cognito-idp.${this.config.region}.amazonaws.com/${this.config.userPoolId}`
			});
			return verifiedToken;
		} catch (error) {
			throw error;
		}
	}

	async isUserLoggedIn(CognitoUserId: string): Promise<boolean> {
		try {
			// Pobierz accessToken z VizStorageService
			const currentTokens = await this.storageService.getCredentials(CognitoUserId);

			if (!currentTokens || !currentTokens.accessToken) {
				return false;
			}

			// Użyj accessToken do wykonania zapytania do Cognito
			const command = new GetUserCommand({
				AccessToken: currentTokens.accessToken,
			});

			const response = await this.client.send(command);
			// Jeśli odpowiedź jest pomyślna, użytkownik jest nadal zalogowany
			return !!response;
		} catch (error) {
			// Jeśli wystąpi błąd (np. TokenExpiredError), użytkownik nie jest zalogowany
			// console.error(error);
			// console.log('isUserLoggedIn:',false );
			return false;
		}
	}

	async refreshToken(CognitoUserId: string): Promise<TokensDto> {
		const currentTokens = await this.storageService.getCredentials(CognitoUserId);

		if (!currentTokens || !currentTokens.refreshToken) {
			throw new Error('Brak tokenu odświeżającego, nie można odświeżyć tokenu');
		}

		const command = new InitiateAuthCommand({
			AuthFlow: 'REFRESH_TOKEN_AUTH',
			ClientId: this.config.clientId,
			AuthParameters: {
				REFRESH_TOKEN: currentTokens.refreshToken,
				SECRET_HASH: this.calculateSecretHash(CognitoUserId),
			},
		});

		try {
			const response = await this.client.send(command);
			const newTokens: TokensDto = {
				accessToken: response.AuthenticationResult?.AccessToken,
				idToken: response.AuthenticationResult?.IdToken,
				refreshToken: response.AuthenticationResult?.RefreshToken || currentTokens.refreshToken, // Użyj nowego, jeśli dostępny
			};

			await this.storageService.updateCredentials(CognitoUserId, newTokens);

			console.log('refreshToken:', CognitoUserId);

			return newTokens;
		} catch (error) {
			throw new Error(error.message);
		}
	}

	extractUserIdFromToken(idToken: string): string {
		try {
			const decodedToken = decode(idToken) as any;
			return decodedToken && decodedToken.sub ? decodedToken.sub : '';
		} catch (error) {
			throw new Error('Błąd podczas dekodowania idToken: ' + error.message);
		}
	}

	async changeUserPassword(idToken: string, oldPassword: string, newPassword: string): Promise<any> {
		const cognitoUserId = this.extractUserIdFromToken(idToken);
		const credentials = await this.storageService.getCredentials(cognitoUserId);

		if (!credentials || !credentials.accessToken) {
			throw new Error('Brak accessToken dla danego użytkownika');
		}

		const command = new ChangePasswordCommand({
			AccessToken: credentials.accessToken,
			PreviousPassword: oldPassword,
			ProposedPassword: newPassword,
		});

		try {
			const response = await this.client.send(command);
			return response;
		} catch (error) {
			throw new Error(error.message);
		}
	}

	async initiatePasswordReset(username: string): Promise<any> {
		const command = new ForgotPasswordCommand({
			ClientId: this.config.clientId,
			Username: username,
			SecretHash: this.calculateSecretHash(username),
		});

		try {
			const response = await this.client.send(command);
			return response; // Odpowiedź zawiera informacje o wysłaniu kodu
		} catch (error) {
			throw new Error(error.message);
		}
	}

	async confirmPasswordReset(username: string, newPassword: string, confirmationCode: string): Promise<any> {
		const command = new ConfirmForgotPasswordCommand({
			ClientId: this.config.clientId,
			Username: username,
			ConfirmationCode: confirmationCode,
			Password: newPassword,
			SecretHash: this.calculateSecretHash(username),
		});

		try {
			const response = await this.client.send(command);
			return response; // Odpowiedź zawiera informacje o zmianie hasła
		} catch (error) {
			throw new Error(error.message);
		}
	}

	async signUp(username: string, password: string, userAttributes: any[]): Promise<any> {
		const command = new SignUpCommand({
			ClientId: this.config.clientId,
			Username: username,
			Password: password,
			SecretHash: this.calculateSecretHash(username),
			UserAttributes: userAttributes, // np. [{ Name: 'email', Value: 'user@example.com' }]
		});

		try {
			const response = await this.client.send(command);
			return response; // Zwraca informacje o statusie rejestracji
		} catch (error) {
			throw new Error(error.message);
		}
	}


}
