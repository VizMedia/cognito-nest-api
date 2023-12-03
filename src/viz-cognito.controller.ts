import { Body, Controller, Get, Post, Req, Res, HttpStatus, UseGuards, HttpCode } from '@nestjs/common';
import { VizCognitoService } from './viz-cognito.service';
import { ApiTags, ApiResponse, ApiOperation, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { VizStorageService } from './viz-storage.service';
import { Response } from 'express';
// import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './interfaces/login-dto';
import { VizCognitoGuard } from './viz-cognito.guard';
import { InitiatePasswordResetDto } from './interfaces/initiate-password-reset';
import { ConfirmPasswordResetDto } from './interfaces/confirm-password-reset';
import { ChangePassword } from './interfaces/change-password';
import { RegisterUserDto } from './interfaces/register-user';
import { ConfirmRegistrationDto } from './interfaces/confirm-registration';

@ApiTags('cognito')
@Controller('cognito')
export class VizCognitoController {
	constructor(
		private readonly cognitoService: VizCognitoService,
		private readonly storageService: VizStorageService,
		// private readonly jwtService: JwtService,
	) { }

	@Post('/register')
	@HttpCode(200)
	@ApiBody({ type: RegisterUserDto })
	async registerUser(
		@Body('username') username: string,
		@Body('password') password: string,
		@Body('email') email: string,
		@Body('phone') phone: string,
		@Res() res: Response
	): Promise<Response> {
		try {
			const response = await this.cognitoService.registerUser(username, password, email, phone);
			return res.json(response);
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/confirm-registration')
	@HttpCode(200)
	@ApiBody({ type: ConfirmRegistrationDto })
	async confirmUserRegistration(
		@Body('username') username: string,
		@Body('code') code: string,
		@Res() res: Response
	): Promise<Response> {
		try {
			const response = await this.cognitoService.confirmUserRegistration(username, code);
			return res.json(response);
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/signin')
	@ApiOperation({ summary: 'AWS SignIn' })
	@ApiResponse({ status: 200, description: 'Returns AWS IdToken - copy this token to Authorization: Bearer .... as http header .' })
	@ApiResponse({ status: 403, description: 'Forbidden' })
	@ApiBody({ type: LoginDto }) // Tutaj definiujemy ciało żądania	
	async signIn(@Body() loginDto: LoginDto, @Res() res: Response): Promise<any> {
		try {
			const result = await this.cognitoService.signIn(loginDto.emailOrPhone, loginDto.password);
			return res.status(HttpStatus.OK).json(result);
		} catch (error) {
			return res.status(HttpStatus.FORBIDDEN).json({
				statusCode: 403,
				message: 'Forbidden ' + error.message,
			});
		}
	}

	@Get('/islogged')
	@ApiOperation({ summary: 'AWS IsLoged' })
	@ApiBearerAuth()
	@ApiResponse({ status: 200, description: 'Returns result and role object.' })
	async isLogged(@Req() req, @Res() res: Response): Promise<any> {
		const idToken = req.headers.authorization?.split(' ')[1];
		if (!idToken) {
			return res.status(HttpStatus.FORBIDDEN).json({
				statusCode: 403,
				message: 'Forbidden',
			});
		}
		const CognitoUserId = this.cognitoService.extractUserIdFromToken(idToken);
		let wynik: boolean = await this.cognitoService.isUserLoggedIn(CognitoUserId);
		if (!wynik) {
			return res.status(HttpStatus.UNAUTHORIZED).json({
				statusCode: 401,
				message: 'not logged',
			});
		} else {
			return res.status(HttpStatus.OK).json({
				statusCode: 200,
				message: 'ok',
			});
		}
	}

	@Post('/signout')
	@UseGuards(VizCognitoGuard)
	@ApiBearerAuth()
	@ApiOperation({ summary: 'AWS SignOut' })
	async signout(@Req() req, @Res() res: Response): Promise<any> {
		const idToken = req.headers.authorization?.split(' ')[1];
		if (!idToken) {
			return res.status(HttpStatus.FORBIDDEN).json({
				statusCode: 403,
				message: 'Forbidden',
			});
		}

		// Wyodrębnienie CognitoUserId z tokena
		const CognitoUserId = this.cognitoService.extractUserIdFromToken(idToken);
		console.log('CognitoUserId', CognitoUserId);
		let wynik = await this.cognitoService.signOut(CognitoUserId);

		if (wynik) {
			return res.status(HttpStatus.OK).json({
				statusCode: 200,
				message: 'signout',
			});
		} else {
			return res.status(HttpStatus.FORBIDDEN).json({
				statusCode: 403,
				message: 'Forbidden',
			});
		}
	}


	// FORGOT PASSWORD

	@Post('/initiate-password-reset')
	@HttpCode(200)
	@ApiBody({ type: InitiatePasswordResetDto })
	async initiatePasswordReset(
		@Body('username') username: string,
		@Res() res: Response
	): Promise<Response> {
		try {
			const response = await this.cognitoService.initiatePasswordReset(username);
			console.log('status inicjacji',response);
			return res.json(response);
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}

	@Post('/confirm-password-reset')
	@HttpCode(200)
	@ApiBody({ type: ConfirmPasswordResetDto })
	async confirmPasswordReset(
		@Body('username') username: string,
		@Body('newPassword') newPassword: string,
		@Body('confirmationCode') confirmationCode: string,
		@Res() res: Response
	): Promise<Response> {
		try {
			const response = await this.cognitoService.confirmPasswordReset(username, newPassword, confirmationCode);
			console.log('status potwierdzenia',response);
			return res.json(response);
		} catch (error) {
			return res.status(400).json({ message: error.message });
		}
	}


	// CHANGE PASSWORD

	@Post('/change-password')
	@UseGuards(VizCognitoGuard)
	@ApiBody({ type: ChangePassword })
	@ApiBearerAuth()
	async changeUserPassword(
		@Req() req,
		@Body('oldPassword') oldPassword: string,
		@Body('newPassword') newPassword: string,
		@Res() res: Response
	): Promise<any> {
		const idToken = req.headers.authorization?.split(' ')[1];
		if (!idToken) {
			return res.status(HttpStatus.FORBIDDEN).json({
				statusCode: 403,
				message: 'Forbidden',
			});
		}

		try {
			const response = await this.cognitoService.changeUserPassword(idToken, oldPassword, newPassword);
			return res.json(response);
		} catch (error) {
			return await res.status(HttpStatus.BAD_REQUEST).json({ message: error.message });
		}
	}


}
