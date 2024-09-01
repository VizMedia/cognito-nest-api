import { Body, Controller, Get, Post, Req, Res, HttpStatus, UseGuards, HttpCode } from '@nestjs/common';
import { VizCognitoService } from './viz-cognito.service';
import { ApiTags, ApiResponse, ApiOperation, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { VizStorageService } from './viz-storage.service';
import { Response } from 'express';
import { LoginDto } from './interfaces/login-dto';
import { VizCognitoGuard } from './viz-cognito.guard';
import { InitiatePasswordResetDto } from './interfaces/initiate-password-reset';
import { ConfirmPasswordResetDto } from './interfaces/confirm-password-reset';
import { ChangePasswordDto } from './interfaces/change-password';
import { RegisterUserDto } from './interfaces/register-user';
import { ConfirmRegistrationDto } from './interfaces/confirm-registration';
import { LoginSessionDto } from './interfaces/login-session';
import { UsernameDto } from './interfaces/username-dto';
import { AddPhoneDto } from './interfaces/add-phone-dto';
import { ConfirmPropertyDto } from './interfaces/confirm-property-dto';
import { AddEmailDto } from './interfaces/add-email-dto';
import { PayInfoDto } from './interfaces/payinfo-dto';

@ApiTags('cognito')
@Controller('cognito')
export class VizCognitoController {

	constructor(
		private readonly cognitoService: VizCognitoService,
		private readonly storageService: VizStorageService,
	) { }

	@Post('/register')
	@ApiOperation({ summary: 'Register a new user' })
	@HttpCode(200)
	@ApiBody({ type: RegisterUserDto })
	@ApiResponse({ status: 200, description: 'The user has been successfully registered.' })
	@ApiResponse({ status: 400, description: 'Bad Request.' })
	async registerUser(
		@Body() registerUserDto: RegisterUserDto,
		@Res() res: Response
	): Promise<Response> {		
		try {
			const response = await this.cognitoService.registerUser(registerUserDto);
			console.log(response.UserSub, 'start register', response.CodeDeliveryDetails.Destination);
			return res.json({
				data: response,
				links: await this.cognitoService.calculateLinksApiInfo(['confirmRegistration', 'registerUser', 'signIn', 'initiatePasswordReset'])
			});
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/confirm-registration')
	@HttpCode(200)
	@ApiOperation({ summary: 'Confirm user registration' })
	@ApiBody({ type: ConfirmRegistrationDto })
	@ApiResponse({ status: 200, description: 'User registration confirmed.' })
	@ApiResponse({ status: 400, description: 'Bad Request.' })
	async confirmUserRegistration(
		@Body() confirmRegistration: ConfirmRegistrationDto,
		@Res() res: Response
	): Promise<Response> {
		try {
			const response = await this.cognitoService.confirmUserRegistration(confirmRegistration);
			console.log(confirmRegistration.username, 'confirm registration');
			return res.json({
				data: response,
				links: await this.cognitoService.calculateLinksApiInfo(['registerUser', 'signIn', 'initiatePasswordReset'])
			});
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/signin')
	@ApiOperation({ summary: 'AWS SignIn' })
	@ApiResponse({ status: 200, description: 'Returns AWS IdToken. Use this token in Authorization: Bearer ... header.' })
	@ApiResponse({ status: 403, description: 'Forbidden' })
	@ApiBody({ type: LoginDto })
	async signIn(@Body() loginDto: LoginDto, @Res() res: Response): Promise<any> {
		try {
			const result = await this.cognitoService.signIn(loginDto.username, loginDto.password);

			if (!result) {
				return res.status(HttpStatus.FORBIDDEN).json({
					statusCode: 403,
					message: 'Forbidden',
				});
			}

			if (result.Session && result.Session.length > 0) {
				console.log(loginDto.username, 'Sign In - Session created');
				return res.json({
					data: result,
					links: await this.cognitoService.calculateLinksApiInfo(['registerUser', 'signInSession', 'initiatePasswordReset'], result.IdToken, result)
				});
			}

			console.log(loginDto.username, 'Sign In');
			return res.json({
				data: result,
				links: await this.cognitoService.calculateLinksApiInfo(['signOut', 'enableMfa', 'disableMfa', 'changePassword', 'addPhone', 'addEmail', 'verifyProperty'], result.IdToken)
			});

		} catch (error) {
			return res.status(HttpStatus.FORBIDDEN).json({
				statusCode: 403,
				message: 'Forbidden ' + error.message,
			});
		}
	}

	@Post('/signinsession')
	@ApiOperation({ summary: 'Sign in using AWS Cognito session' })
	@ApiResponse({ status: 200, description: 'Returns AWS IdToken. Use this token in Authorization: Bearer ... header.' })
	@ApiResponse({ status: 403, description: 'Forbidden' })
	@ApiBody({ type: LoginSessionDto })
	async signInSession(@Body() loginSession: LoginSessionDto, @Res() res: Response): Promise<any> {
		try {
			const result = await this.cognitoService.signInSession(loginSession);
			return res.json({
				data: result,
				links: await this.cognitoService.calculateLinksApiInfo(['signOut', 'enableMfa', 'disableMfa', 'changePassword', 'addPhone', 'addEmail', 'verifyProperty'], result.IdToken, result)
			});

		} catch (error) {
			return res.status(HttpStatus.FORBIDDEN).json({
				statusCode: 403,
				message: 'Forbidden ' + error.message,
			});
		}
	}

	@Get('/islogged')
	@ApiOperation({ summary: 'Check if the user is logged in' })
	@ApiBearerAuth()
	@ApiResponse({ status: 200, description: 'Returns result and role object.' })
	async isLogged(@Req() req, @Res() res: Response): Promise<any> {
		let payinfo: PayInfoDto = await this.cognitoService.getInfoFromRequest(req);
		
		let wynik = await this.cognitoService.isUserLoggedIn(payinfo.CognitoUserId);
		console.log(payinfo.CognitoUserId, 'is logged', wynik.isLogged);
		if (!wynik.isLogged) {
			return res.status(HttpStatus.UNAUTHORIZED).json({
				statusCode: 401,
				message: 'not logged',
			});
		} else {
			return res.status(HttpStatus.OK).json({
				statusCode: 200,
				message: 'ok',
				data: wynik,
			});
		}
	}

	@Post('/userinfo')
	@UseGuards(VizCognitoGuard)
	@ApiBearerAuth()
	@ApiOperation({ summary: 'Get user information' })
	@ApiResponse({ status: 200, description: 'Returns user information.' })
	async getUserInfo(@Req() req, @Res() res: Response): Promise<any> {
		let payinfo: PayInfoDto = await this.cognitoService.getInfoFromRequest(req);
		const result = await this.cognitoService.getUserInfo(payinfo.CognitoUserId);
		console.log(payinfo.CognitoUserId, 'get user info');
		return res.status(HttpStatus.OK).json({
			statusCode: 200,
			message: 'User info retrieved successfully.',
			data: result,
			links: await this.cognitoService.calculateLinksApiInfo(['signOut', 'enableMfa', 'disableMfa', 'changePassword', 'addPhone', 'addEmail', 'verifyProperty'], payinfo.idToken)
		});
	}

	@Post('/enablemfa')
	@UseGuards(VizCognitoGuard)
	@ApiBearerAuth()
	@ApiOperation({ summary: 'Enable SMS-based multi-factor authentication (MFA)' })
	@ApiResponse({ status: 200, description: 'MFA enabled.' })
	@ApiResponse({ status: 403, description: 'Forbidden.' })
	async enableMFASMS(
		@Req() req,
		@Res() res: Response): Promise<any> {
		try {
			let payinfo: PayInfoDto = await this.cognitoService.getInfoFromRequest(req);
			const result = await this.cognitoService.enableMFA(payinfo.username, payinfo.CognitoUserId);

			console.log(payinfo.CognitoUserId, 'enableMFA SMS');
			return res.status(HttpStatus.OK).json({
				statusCode: 200,
				message: 'MFA enabled successfully.',
				data: result,
				links: await this.cognitoService.calculateLinksApiInfo(['signOut', 'enableMfa', 'disableMfa', 'changePassword', 'addPhone', 'addEmail', 'verifyProperty'], payinfo.idToken)
			});

		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/addphonenumber')
	@UseGuards(VizCognitoGuard)
	@ApiBearerAuth()
	@ApiOperation({ summary: 'Add phone number to user profile' })
	@ApiResponse({ status: 200, description: 'Phone number added.' })
	@ApiResponse({ status: 403, description: 'Forbidden.' })
	@ApiBody({ type: AddPhoneDto })
	async addTelephoneNumber(
		@Body() phoneInfo: AddPhoneDto,
		@Req() req,
		@Res() res: Response): Promise<any> {
		try {
			let payinfo: PayInfoDto = await this.cognitoService.getInfoFromRequest(req);
			let wynik = await this.cognitoService.addTelephoneNumber(phoneInfo, payinfo.CognitoUserId);
			console.log(payinfo.CognitoUserId, 'add phone property');
			return res.status(HttpStatus.OK).json({
				statusCode: 200,
				message: 'Phone number added successfully.',
				data: wynik,
				links: await this.cognitoService.calculateLinksApiInfo(['signOut', 'enableMfa', 'disableMfa', 'changePassword', 'addPhone', 'addEmail', 'verifyProperty'], payinfo.idToken)
			});
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/addemail')
	@UseGuards(VizCognitoGuard)
	@ApiBearerAuth()
	@ApiOperation({ summary: 'Add email to user profile' })
	@ApiResponse({ status: 200, description: 'Email added.' })
	@ApiResponse({ status: 403, description: 'Forbidden.' })
	@ApiBody({ type: AddEmailDto })
	async addEmail(
		@Body() emailInfo: AddEmailDto,
		@Req() req,
		@Res() res: Response): Promise<any> {
		try {
			let payinfo: PayInfoDto = await this.cognitoService.getInfoFromRequest(req);
			let wynik = await this.cognitoService.addEmail(emailInfo, payinfo.CognitoUserId);
			console.log(payinfo.CognitoUserId, 'add email property');
			return res.status(HttpStatus.OK).json({
				statusCode: 200,
				message: 'Email added successfully.',
				data: wynik,
				links: await this.cognitoService.calculateLinksApiInfo(['signOut', 'enableMfa', 'disableMfa', 'changePassword', 'addPhone', 'addEmail', 'verifyProperty'], payinfo.idToken)
			});
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/verifyproperty')
	@UseGuards(VizCognitoGuard)
	@ApiBearerAuth()
	@ApiOperation({ summary: 'Verify phone number' })
	@ApiResponse({ status: 200, description: 'Phone number verified.' })
	@ApiResponse({ status: 403, description: 'Forbidden.' })
	@ApiBody({ type: ConfirmPropertyDto })
	async verifyProperty(
		@Body() verifyproperty: ConfirmPropertyDto,
		@Req() req,
		@Res() res: Response): Promise<any> {
		try {
			let payinfo: PayInfoDto = await this.cognitoService.getInfoFromRequest(req);
			let wynik = await this.cognitoService.verifyProperty(verifyproperty, payinfo.CognitoUserId);
			console.log(payinfo.CognitoUserId, 'verify property '+verifyproperty.attributeName);
			return res.status(HttpStatus.OK).json({
				statusCode: 200,
				message: 'Property verified successfully.',
				data: wynik,
				links: await this.cognitoService.calculateLinksApiInfo(['signOut', 'enableMfa', 'disableMfa', 'changePassword', 'addPhone', 'addEmail', 'verifyProperty'], payinfo.idToken)
			});
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/disablemfa')
	@UseGuards(VizCognitoGuard)
	@ApiBearerAuth()
	@ApiOperation({ summary: 'Disable multi-factor authentication (MFA)' })
	@ApiResponse({ status: 200, description: 'MFA disabled.' })
	@ApiResponse({ status: 403, description: 'Forbidden.' })
	async disableMFA(
		@Req() req,
		@Res() res: Response): Promise<any> {
		try {
			let payinfo: PayInfoDto = await this.cognitoService.getInfoFromRequest(req);
			let wynik = await this.cognitoService.disableMFA(payinfo.username, payinfo.CognitoUserId);
			console.log(payinfo.CognitoUserId, 'disableMFA');
			return res.status(HttpStatus.OK).json({
				statusCode: 200,
				message: 'MFA disabled successfully.',
				data: wynik,
				links: await this.cognitoService.calculateLinksApiInfo(['signOut', 'enableMfa', 'changePassword', 'addPhone', 'addEmail', 'verifyProperty'], payinfo.idToken)
			});
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/signout')
	@UseGuards(VizCognitoGuard)
	@ApiBearerAuth()
	@ApiOperation({ summary: 'Sign out from AWS Cognito' })
	@ApiResponse({ status: 200, description: 'Successfully signed out.' })
	@ApiResponse({ status: 403, description: 'Forbidden.' })
	async signout(@Req() req, @Res() res: Response): Promise<any> {
		try {
			let payinfo: PayInfoDto = await this.cognitoService.getInfoFromRequest(req);
			let wynik = await this.cognitoService.signOut(payinfo.CognitoUserId);
			console.log(payinfo.CognitoUserId, 'sign out');
			return res.status(HttpStatus.OK).json({
				statusCode: 200,
				message: 'signout',
				data: wynik,
				links: await this.cognitoService.calculateLinksApiInfo(['registerUser', 'signIn', 'initiatePasswordReset'])
			});

		} catch (error) {
			return res.status(400).json({ message: error.message });
		}

	}

	@Post('/initiate-password-reset')
	@HttpCode(200)
	@ApiBody({ type: InitiatePasswordResetDto })
	async initiatePasswordReset(
		@Body() forgotAttr: InitiatePasswordResetDto,
		@Res() res: Response
	): Promise<Response> {
		try {
			const response = await this.cognitoService.initiatePasswordReset(forgotAttr);
			console.log(forgotAttr.username, 'initiate password reset');
			return res.json({
				data: response,
				req: forgotAttr,
				links: await this.cognitoService.calculateLinksApiInfo(['confirmPasswordReset', 'registerUser', 'signIn', 'initiatePasswordReset' ])
			});
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/confirm-password-reset')
	@HttpCode(200)
	@ApiBody({ type: ConfirmPasswordResetDto })
	async confirmPasswordReset(
		@Body() confirmPassRes: ConfirmPasswordResetDto,
		@Res() res: Response
	): Promise<Response> {
		try {
			const response = await this.cognitoService.confirmPasswordReset(confirmPassRes);
			console.log(confirmPassRes.username, 'confirm password reset');
			return res.json({
				data: response,
				req: confirmPassRes,
				links: await this.cognitoService.calculateLinksApiInfo(['confirmPasswordReset', 'registerUser', 'signIn', 'initiatePasswordReset'])
			});
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/change-password')
	@UseGuards(VizCognitoGuard)
	@ApiBody({ type: ChangePasswordDto })
	@ApiBearerAuth()
	async changeUserPassword(
		@Req() req,
		@Body() changePassword: ChangePasswordDto,
		@Res() res: Response
	): Promise<any> {
		let payinfo: PayInfoDto = await this.cognitoService.getInfoFromRequest(req);
		try {
			const response = await this.cognitoService.changeUserPassword(changePassword, payinfo.CognitoUserId);
			console.log(payinfo.CognitoUserId, 'change password');
			return res.json({
				data: response,
				req: changePassword,
				links: await this.cognitoService.calculateLinksApiInfo(['signOut', 'enableMfa', 'disableMfa', 'changePassword', 'addPhone', 'addEmail', 'verifyProperty'], payinfo.idToken)
			});
		} catch (error) {
			return await res.status(HttpStatus.BAD_REQUEST).json({ message: error.message });
		}
	}


}
