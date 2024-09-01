import { Injectable, Inject, InternalServerErrorException, Logger } from '@nestjs/common';
import { VizCognitoConfig } from './interfaces/viz-cognito-config.interface';
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
	AdminSetUserMFAPreferenceCommand,
	AdminGetUserCommand,
	AdminGetUserResponse,
	UpdateUserAttributesCommand,
	VerifyUserAttributeCommand
} from '@aws-sdk/client-cognito-identity-provider';
import { createHmac } from 'crypto';
import jwksClient from 'jwks-rsa';
import * as jwt from 'jsonwebtoken';
import { VizStorageService } from './viz-storage.service';
import { TokensDto } from './interfaces/tokens-dto';
import { decode } from 'jsonwebtoken';
import { LoginSessionDto } from './interfaces/login-session';
import { RegisterUserDto } from './interfaces/register-user';
import { ApiLinkDto } from './interfaces/apilink-dto';
import { ConfirmRegistrationDto } from './interfaces/confirm-registration';
import { InitiatePasswordResetDto } from './interfaces/initiate-password-reset';
import { ConfirmPasswordResetDto } from './interfaces/confirm-password-reset';
import { ChangePasswordDto } from './interfaces/change-password';
import { AddPhoneDto } from './interfaces/add-phone-dto';
import { ConfirmPropertyDto } from './interfaces/confirm-property-dto';
import { AddEmailDto } from './interfaces/add-email-dto';
import { PayInfoDto } from './interfaces/payinfo-dto';

@Injectable()
export class VizCognitoService {

	private readonly logger = new Logger(VizCognitoService.name);

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

	async registerUser(registerUser: RegisterUserDto): Promise<any> {

		const attributes = [];

		if (registerUser.email && registerUser.email.length > 0 && registerUser.preferredMethod.toLocaleLowerCase() === 'email') {
			attributes.push({ Name: 'email', Value: registerUser.email });
		}

		if (registerUser.phone && registerUser.phone.length > 0 && registerUser.preferredMethod.toLocaleLowerCase() === 'sms') {
			attributes.push({ Name: 'phone_number', Value: registerUser.phone });
		}

		if (attributes.length < 1) {
			this.logger.error('email address or phone number required');
			throw new Error('email address or phone number required');
		}

		const secretHash = this.calculateSecretHash(registerUser.username);

		const command = new SignUpCommand({
			ClientId: this.config.clientId,
			SecretHash: secretHash,
			Username: registerUser.username,
			Password: registerUser.password,
			UserAttributes: attributes,
		});

		try {
			const response = await this.client.send(command);
			return response;
		} catch (error) {
			this.logger.error('regiesterUser Error:', error);
			throw new InternalServerErrorException(`Registration failed: ${error.message}`);
		}
	}

	async confirmUserRegistration(confirmRegistrationUser: ConfirmRegistrationDto): Promise<any> {

		const secretHash = this.calculateSecretHash(confirmRegistrationUser.username);

		const command = new ConfirmSignUpCommand({
			ClientId: this.config.clientId,
			SecretHash: secretHash,
			Username: confirmRegistrationUser.username,
			ConfirmationCode: confirmRegistrationUser.code,
		});

		try {
			const response = await this.client.send(command);
			return response;
		} catch (error) {
			this.logger.error('confirmUserRegistration Error:', error);
			throw new Error(error.message);
		}
	}

	async signIn(username: string, password: string): Promise<any> {

		const secretHash = this.calculateSecretHash(username);

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

			const response = await this.client.send(command);

			if (response.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
				return {
					challengeName: 'NEW_PASSWORD_REQUIRED',
					session: response.Session,
					userAttributes: JSON.parse(response.ChallengeParameters.userAttributes),
				};
			}

			if (response.ChallengeName === 'SMS_MFA') {
				console.log(username+'wymagany SMS_MFA');
				return response;
			}

			if (response.ChallengeName === 'SOFTWARE_TOKEN_MFA') {
				console.log(username+'wymagany SOFTWARE_TOKEN_MFA');
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
			this.logger.error(`${username} signIn Error: ${error.message}`);
			// throw new Error(error.message);
		}
	}

	async addTelephoneNumber(phone: AddPhoneDto, CognitoUserId: string): Promise<any> {

		const currentTokens = await this.storageService.getCredentials(CognitoUserId);

		if (!currentTokens || !currentTokens.accessToken) {
			throw new Error('error accessToken');
		}

		const params = {
			AccessToken: currentTokens.accessToken,
			UserAttributes: [
				{
					Name: "phone_number",
					Value: phone.phoneNumber,
				},
			],
		};

		const command = new UpdateUserAttributesCommand(params);

		try {
			const response = await this.client.send(command);
			return response;
		} catch (error) {
			this.logger.error(`Error adding telephone number: ${error.message}`, error);
			throw new Error(`${CognitoUserId} Error adding telephone number: ${error.message}`);
		}
	}

	async verifyProperty(verifyproperty: ConfirmPropertyDto, CognitoUserId: string): Promise<any> {

		const currentTokens = await this.storageService.getCredentials(CognitoUserId);

		if (!currentTokens || !currentTokens.accessToken) {
			throw new Error('error accessToken');
		}

		const params = {
			AccessToken: currentTokens.accessToken,
			Code: verifyproperty.code,
			AttributeName: verifyproperty.attributeName
		};

		const command = new VerifyUserAttributeCommand(params);
		try {
			const response = await this.client.send(command);
			return response;
		} catch (err) {
			this.logger.error(`Error verify Property: ${err.message}`, err.message);
			throw new Error(err.message);
		}
	}

	async addEmail(email: AddEmailDto, CognitoUserId: string): Promise<any> {
		const currentTokens = await this.storageService.getCredentials(CognitoUserId);
		if (!currentTokens || !currentTokens.accessToken) {
			throw new Error('error accessToken');
		}

		const params = {
			AccessToken: currentTokens.accessToken,
			UserAttributes: [
				{
					Name: "email",
					Value: email.email,
				},
			],
		};

		const command = new UpdateUserAttributesCommand(params);

		try {
			const response = await this.client.send(command);
			return response;
		} catch (error) {
			this.logger.error(`Error adding email: ${error.message}`, error);
			throw new Error(`${CognitoUserId} Error adding email: ${error.message}`);
		}
	}

	async enableMFA(username: string, CognitoUserId: string): Promise<any> {
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
			this.logger.error(`Error enabling MFA: ${error.message}`, error);
			throw new Error(`${username} Error enabling MFA: ${error.message}`);
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
			this.logger.error(`Error enabling MFA: ${error.message}`, error);
			throw new Error(`${username} Error enabling MFA: ${error.message}`);
		}
	}

	async signInSession(loginSession: LoginSessionDto): Promise<any> { // response: any, mfaCode: string, challengeName: string): Promise<any> {

		try {
			const secretHash = this.calculateSecretHash(loginSession.username);

			console.log('loginSession for username', loginSession.username);

			let challengeName: string = '';
			let challengeNameCode: string = '';
			switch (loginSession?.medium) { //CODE_DELIVERY_DELIVERY_MEDIUM
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

			let command = new RespondToAuthChallengeCommand({
				ClientId: this.config.clientId,
				ChallengeName: challengeName,
				Session: loginSession.session,
				ChallengeResponses: {
					[challengeNameCode]: loginSession.mfacode,
					USERNAME: loginSession.username, //USER_ID_FOR_SRP
					SECRET_HASH: secretHash,
				},
			});

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
			this.logger.error(`Error respondToMFAChallenge: ${this.config.clientId} ${error.message}`, error);
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
			return response;
		} catch (error) {
			this.logger.error(`Error signOut: ${CognitoUserId} ${error.message}`, error);
			throw new Error(error.message);
		}
	}

	async isUserLoggedIn(CognitoUserId: string): Promise<any> {
		try {
			const currentTokens = await this.storageService.getCredentials(CognitoUserId);

			if (!currentTokens || !currentTokens.accessToken) {
				return false;
			}

			const command = new GetUserCommand({
				AccessToken: currentTokens.accessToken,
			});

			const response = await this.client.send(command);

			let wynik = !!response;

			return await {
				isLogged: wynik,
				userId: CognitoUserId,
			}
		} catch (error) {
			this.logger.error(`Error isUserLoggedIn: ${CognitoUserId} ${error.message}`, error);
			return false;
		}
	}

	async getUserInfo(CognitoUserId: string): Promise<any> {
		try {
			const currentTokens = await this.storageService.getCredentials(CognitoUserId);

			if (!currentTokens || !currentTokens.accessToken) {
				throw new Error('no accessToken for this user');
			}

			const command = new GetUserCommand({
				AccessToken: currentTokens.accessToken,
			});

			const response = await this.client.send(command);
			return response;
		} catch (error) {
			throw new Error(error.message);
		}
	}

	async refreshToken(CognitoUserId: string, currentDbTokens: TokensDto): Promise<TokensDto> {

		if (!currentDbTokens || !currentDbTokens.refreshToken) {
			throw new Error('no refreshToken in Db');
		}

		let decodedAccessToken = decode(currentDbTokens.accessToken) as any;

		const command = new InitiateAuthCommand({
			AuthFlow: 'REFRESH_TOKEN_AUTH',
			ClientId: this.config.clientId,
			AuthParameters: {
				REFRESH_TOKEN: currentDbTokens.refreshToken,
				SECRET_HASH: this.calculateSecretHash(decodedAccessToken.username),
			},
		});

		try {
			const response = await this.client.send(command);
			const newTokens: TokensDto = {
				accessToken: response.AuthenticationResult?.AccessToken,
				idToken: response.AuthenticationResult?.IdToken,
				refreshToken: response.AuthenticationResult?.RefreshToken || currentDbTokens.refreshToken, // Użyj new if exists, else old
			};

			return newTokens;
		} catch (error) {
			console.log('refresh problem: ', error.message);
			//throw new Error(error.message);
		}
	}

	async changeUserPassword(changeUserPassword: ChangePasswordDto, cognitoUserId: string): Promise<any> {
		const credentials = await this.storageService.getCredentials(cognitoUserId);

		if (!credentials || !credentials.accessToken) {
			throw new Error('Brak accessToken dla danego użytkownika');
		}

		const command = new ChangePasswordCommand({
			AccessToken: credentials.accessToken,
			PreviousPassword: changeUserPassword.oldPassword,
			ProposedPassword: changeUserPassword.newPassword,
		});

		try {
			const response = await this.client.send(command);
			return response;
		} catch (error) {
			this.logger.error(`Error changeUserPassword: ${cognitoUserId} ${error.message}`, error);
			throw new Error(error.message);
		}
	}

	async getUserByUsername(username: string): Promise<AdminGetUserResponse> {

		console.log('this.config.userPoolId', this.config.userPoolId);

		const command = new AdminGetUserCommand({
			UserPoolId: this.config.userPoolId,
			Username: username,
		});

		try {
			const response = await this.client.send(command);
			return response;
		} catch (error) {
			throw new Error(error.message);
		}
	}

	async initiatePasswordReset(initiatePasswordReset: InitiatePasswordResetDto): Promise<any> {
		try {

			const command = new ForgotPasswordCommand({
				ClientId: this.config.clientId,
				Username: initiatePasswordReset.username,
				SecretHash: this.calculateSecretHash(initiatePasswordReset.username),
			});

			const response = await this.client.send(command);
			return response;
		} catch (error) {
			throw new Error(error.message);
		}
	}

	async confirmPasswordReset(confirmPassRes: ConfirmPasswordResetDto): Promise<any> {
		const command = new ConfirmForgotPasswordCommand({
			ClientId: this.config.clientId,
			Username: confirmPassRes.username,
			ConfirmationCode: confirmPassRes.confirmationCode,
			Password: confirmPassRes.newPassword,
			SecretHash: this.calculateSecretHash(confirmPassRes.username),
		});

		try {
			const response = await this.client.send(command);
			return response;
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

	async calculateLinksApiInfo(possibleLinks: Array<string>, idToken: string | null = null, Session: any | null = null): Promise<any> {
		let decodedToken = null;
		let CognitoUserId = null;
		let isLogged: boolean = false;
		if (idToken) {
			decodedToken = await decode(idToken) as any;
			CognitoUserId = await this.extractUserIdFromToken(idToken);
			isLogged = await this.isUserLoggedIn(CognitoUserId)
		}

		let links: Array<ApiLinkDto> = [];

		if (possibleLinks) {
			possibleLinks.forEach((link) => {

				let ln: ApiLinkDto = { rel: '', href: '', method: '', description: '', payload: {} };

				switch (link) {
					case 'registerUser':
						if (!isLogged) {
							ln.href = '/cognito/register';
							ln.method = 'POST';
							ln.description = 'Register a new user';
							ln.payload = {
								"username": "<username>",
								"password": "<password>",
								"email": "<email>",
								"phone": "<phone>",
								"preferredMethod": "<SMS | EMAIL>"
							};
						}
						break;
					case 'confirmRegistration':
						if (!isLogged) {
							ln.href = '/cognito/confirm-registration';
							ln.method = 'POST';
							ln.description = 'Confirm user registration';
							ln.payload = {
								"username": "<username | email(if prefered) | phoneNumber(if prefered)",
								"code": "<confirmation code>"
							};
						}
						break;
					case 'signIn':
						if (!isLogged && !Session) {
							ln.href = '/cognito/signin';
							ln.method = 'POST';
							ln.description = 'Sign in';
							ln.payload = {
								"username": "<username | email(if prefered) | phoneNumber(if prefered)>",
								"password": "<password>"
							};
						}
						break;
					case 'enableMfa':
						if (decodedToken && decodedToken.phone_number && decodedToken.phone_number_verified && isLogged) {
							ln.href = '/cognito/enablemfa';
							ln.method = 'POST';
							ln.description = 'Enable MFA';
							ln.payload = {
								"username": "<username | email(if prefered) | phoneNumber(if prefered)>"
							};
						}
						break;
					case 'disableMfa':
						if (isLogged) {
							ln.href = '/cognito/disablemfa';
							ln.method = 'POST';
							ln.description = 'Disable MFA';
							ln.payload = {
								"username": "<username | email(if prefered) | phoneNumber(if prefered)>"
							};
						}
						break;
					case 'signOut':
						if (isLogged) {
							ln.href = '/cognito/signout';
							ln.method = 'POST';
							ln.description = 'Sign out';
							ln.payload = {};
						};
						break;
					case 'initiatePasswordReset':
						if (!isLogged) {
							ln.href = '/cognito/initiate-password-reset';
							ln.method = 'POST';
							ln.description = 'Initiate password reset';
							ln.payload = {
								"username": "<username | email(if prefered) | phoneNumber(if prefered)>",
								"preferredMethod": "<SMS | EMAIL>"
							};
						}
						break;
					case 'signInSession':
						if (Session && !isLogged) {
							ln.href = '/cognito/signinsession';
							ln.method = 'POST';
							ln.description = 'Sign in session with MFA - waiting for MFA code and run this endpoint';
							ln.payload = {
								"username": Session.ChallengeParameters.USER_ID_FOR_SRP,
								"mfacode": "<mfa code>",
								"session": Session.Session,
								"medium": Session.ChallengeParameters.CODE_DELIVERY_DELIVERY_MEDIUM
							};
						};
						break;
					case 'confirmPasswordReset':
						if (!isLogged) {
							ln.href = '/cognito/confirm-password-reset';
							ln.method = 'POST';
							ln.description = 'Confirm password reset with new password and confirmation code';
							ln.payload = {
								"username": "<username | email(if prefered) | phoneNumber(if prefered)>",
								"newPassword": "<new password>",
								"confirmationCode": "<confirmation code>"
							};
						}
						break;
					case 'changePassword':
						if (isLogged) {
							ln.href = '/cognito/change-password';
							ln.method = 'POST';
							ln.description = 'Change user password';
							ln.payload = {
								"oldPassword": "<old password>",
								"newPassword": "<new password>"
							};
						}
						break;
					case 'addPhone':
						if (decodedToken && decodedToken.phone_number_verified === 'false' && isLogged) {
							ln.href = '/cognito/addphone';
							ln.method = 'POST';
							ln.description = 'Add phone number';
							ln.payload = {
								"username": "<username | email(if prefered) | phoneNumber(if prefered)>",
								"phoneNumber": "<phone number>"
							};
						}
						break;
					case 'addEmail':
						if (decodedToken && decodedToken.email_verified === 'false' && isLogged) {
							ln.href = '/cognito/addemail';
							ln.method = 'POST';
							ln.description = 'Add email address';
							ln.payload = {
								"email": "<email address>"
							};
						}
						break;
					case 'verifyProperty':
						if (isLogged) {
							ln.href = '/cognito/verifyproperty';
							ln.method = 'POST';
							ln.description = 'Verify phone number';
							ln.payload = {
								"code": "<verification code>"
							};
						}
						break;
					default:
						break;
				}

				ln.rel = link;
				if (ln.href.length > 0)
					links.push(ln);
			});
		}

		return links;

	}

	private calculateSecretHash(username: string): string {
		const secretHash = createHmac('sha256', this.config.clientSecret) // Użyj Twojego client secret
			.update(username + this.config.clientId)
			.digest('base64');
		return secretHash;
	}

	extractUserIdFromToken(idToken: string): string {
		try {
			const decodedToken = decode(idToken) as any;
			return decodedToken && decodedToken.sub ? decodedToken.sub : '';
		} catch (error) {
			throw new Error('Błąd podczas dekodowania idToken: ' + error.message);
		}
	}

	public async getInfoFromRequest(req: any): Promise<PayInfoDto> {
		const idToken = await req.headers.authorization?.split(' ')[1];
		const decoded = await decode(idToken) as any;
		const CognitoUserId = decoded ? decoded.sub : '';
		const username = decoded ? decoded['cognito:username'] : '';
		return await { idToken, CognitoUserId, username };
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
			throw new Error('Token verification failed: ' + error.message);
		}
	}

}
