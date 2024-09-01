import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { VizCognitoService } from './viz-cognito.service';
import { JsonWebTokenError, TokenExpiredError } from '@nestjs/jwt';
import { VizStorageService } from './viz-storage.service';
import { decode } from 'jsonwebtoken';


@Injectable()
export class VizCognitoGuard implements CanActivate {
  constructor(
    private readonly cognitoService: VizCognitoService,
    private readonly storageService: VizStorageService
  ) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    let inHeaderToken = await request.headers.authorization?.split(' ')[1];

    

    if (!inHeaderToken) {
      return await false;
    }

    const CognitoUserId = await this.extractUserIdFromToken(inHeaderToken);

    let currentDbTokens = await this.storageService.getCredentials(CognitoUserId);
    if (!currentDbTokens) {
      return await false;
    }

        // check if inHeaderToken is same as in DB
    if (currentDbTokens.idToken !== inHeaderToken) {
      console.log(CognitoUserId, 'GUARD: inHeaderToken is not same as in DB');
      return await false;
    } 

    try {
      await this.cognitoService.verifyToken(inHeaderToken);
      return true;
    } catch (error) {

      console.log(CognitoUserId, 'GUARD: token error:', error.message);
 
      if (error instanceof TokenExpiredError) {
        const newTokens = await this.cognitoService.refreshToken(CognitoUserId, currentDbTokens);

        if(!newTokens.idToken || newTokens.idToken.length < 10) {
          console.log(CognitoUserId, 'GUARD: token refresh failed');
          return false;
        }

        

        response.setHeader('X-Refresh-Token-Updated', `${newTokens.idToken}`);
        request.headers.authorization = `Bearer ${newTokens.idToken}`;

        await this.storageService.updateCredentials(CognitoUserId, newTokens);
        console.log(CognitoUserId, 'GUARD: token refreshed');
        return true;
      }

      console.log(CognitoUserId, 'GUARD: token failed: ', error.message);

      return false;
    }
  }

  private extractUserIdFromToken(token: string): string {
    const decodedToken = decode(token) as any;
    return decodedToken ? decodedToken.sub : '';
  }
}



// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
// https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json



