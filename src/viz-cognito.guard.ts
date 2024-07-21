import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { VizCognitoService } from './viz-cognito.service';
import { TokenExpiredError } from '@nestjs/jwt';
import { VizStorageService } from './viz-storage.service';
import { decode } from 'jsonwebtoken';




@Injectable()
export class VizCognitoGuard implements CanActivate {
  constructor(
    private readonly cognitoService: VizCognitoService,
    private readonly storageService: VizStorageService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    try {
      const token = request.headers.authorization?.split(' ')[1];
      if (!token) {
        return false; // Brak tokenu, zwróć false
      }
			
			const CognitoUserId = this.extractUserIdFromToken(token);
			
			// Sprawdź czy token jest ważny
      
			const isUserLoggedIn = await this.cognitoService.isUserLoggedIn(CognitoUserId);
			if (!isUserLoggedIn) {
				return false;
			}

      try {
        await this.cognitoService.verifyToken(token);
        return true; // Token zweryfikowany pomyślnie
      } catch (error) {
        // Sprawdź czy to błąd wygaśnięcia tokenu

        if (error instanceof TokenExpiredError) {
					
					// Wykonaj odświeżanie tokena

          console.log('test');
          
          const newTokens = await this.cognitoService.refreshToken(CognitoUserId);

          // Ustaw nowy AccessToken w nagłówku odpowiedzi
          // response.setHeader('Authorization', `Bearer ${newTokens.accessToken}`);
          response.setHeader('Authorization', `Bearer ${newTokens.idToken}`);

          // Kontynuuj z nowym tokenem
          return true;
        }

        // Inny błąd weryfikacji tokenu
        console.error('guard error:',error.message);
        return false;
      }
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  private extractUserIdFromToken(token: string): string {
    // Dekoduj token i ekstraktuj identyfikator użytkownika Cognito
    const decodedToken = decode(token) as any;
    return decodedToken ? decodedToken.sub : '';
  }
}

















// @Injectable()
// export class VizCognitoGuard implements CanActivate {
//   constructor(private readonly cognitoService: VizCognitoService) {}

//   async canActivate(context: ExecutionContext): Promise<boolean> {
//     const request = context.switchToHttp().getRequest();
//     try {
//       const token = request.headers.authorization?.split(' ')[1];
//       if (!token) {
//         return false; // Brak tokenu, zwróć false
//       }
//       await this.cognitoService.verifyToken(token);
//       return true; // Token zweryfikowany pomyślnie
//     } catch (error) {
//       console.error(error); // Opcjonalnie, zaloguj błąd
//       return false; // Wystąpił błąd weryfikacji, zwróć false
//     }
//   }
// }






























// 			// Możesz dodać dodatkowe sprawdzenia dla dekodowanego tokena, jeśli są potrzebne
// 			//TODO: weryfikacja tokenu jest tutaj:
// 			// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
// 			// https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
// 			// klucz publiczny z AWS do weryfikacji tokenu powinienem pobrać przy logowaniu i zapisać w storage



// Użytkownik loguje się przez AWS Cognito.
// AWS Cognito zwraca trzy tokeny.
// Backend generuje własny unikalny token sesji.
// Backend zapisuje trzy tokeny od AWS Cognito w storage, używając tokena sesji jako klucza/identyfikatora.
// Backend zwraca token sesji do klienta.
// Klient przechowuje token sesji i dołącza go do każdego zapytania do serwera.
// Gdy serwer otrzymuje zapytanie z tokenem sesji, wyszukuje on odpowiednie tokeny w storage i używa ich do autoryzacji lub odnawiania tokenów.
// Jeśli Access Token wygaśnie, backend może użyć Refresh Tokena, aby uzyskać nowy Access Token. Ponieważ klient używa tylko tokena sesji, nie musi się martwić odnawianiem Access Tokena. Jeśli jednak token sesji wygaśnie lub zostanie unieważniony, klient musi się ponownie zalogować.

// Ta strategia ma kilka zalet:

// Bezpieczeństwo: Rzeczywiste tokeny są przechowywane tylko po stronie serwera, co zmniejsza ryzyko ich wycieku.
// Kontrola: Możesz łatwo kontrolować i unieważniać sesje użytkowników po stronie serwera.
// Elastyczność: Możesz łatwo wprowadzać zmiany w sposobie autoryzacji po stronie serwera bez wpływu na klienta.
// Jednak wprowadzenie tej strategii wymaga dodatkowej logiki zarówno po stronie klienta, jak i serwera, więc warto rozważyć, czy korzyści z niej wynikające są odpowiednie dla Twojego konkretnego przypadku użycia.
