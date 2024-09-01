import { Module, DynamicModule } from '@nestjs/common';
import { VizCognitoService } from './viz-cognito.service';
import { VizCognitoController } from './viz-cognito.controller';
import { VizCognitoConfig } from './interfaces/viz-cognito-config.interface';
import { VizStorageService } from './viz-storage.service';
import { VizCognitoGuard } from './viz-cognito.guard';

@Module({})
export class VizCognitoModule {

	static forRoot(options: VizCognitoConfig): DynamicModule {
		return {
			module: VizCognitoModule,
			controllers: [
				VizCognitoController
			],
			providers: [
				VizCognitoService,
				{
					provide: 'VIZ_COGNITO_CONFIG',
					useValue: options,
				},
				VizStorageService,
				VizCognitoGuard,
				// Dodanie dostawcy dla konfiguracji bazy danych, jeśli jest dostarczona
				options.dbConfig && {
					provide: 'VIZ_DATABASE_CONFIG',
					useValue: options.dbConfig,
				}
			].filter(provider => provider), // Filtrowanie, aby usunąć undefined
			exports: [VizCognitoService, VizCognitoGuard, VizStorageService],
		};
	}
}


