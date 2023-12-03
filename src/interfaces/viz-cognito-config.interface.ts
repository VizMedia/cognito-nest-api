import { DatabaseConfig } from "./database-config";

export interface VizCognitoConfig {
  region: string;
	userPoolId: string;
  clientId: string;
	identityPoolId: string;
	clientSecret: string;

	dbConfig?: DatabaseConfig;
  // ... inne wymagane pola konfiguracyjne
}
