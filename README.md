# Cognito Nest API Module

[![npm version](https://badge.fury.io/js/%40vizmedia%2Fcognito-nest-api.svg)](https://www.npmjs.com/package/@vizmedia/cognito-nest-api)

## Description

Cognito Nest API Module is a NestJS module designed to integrate with AWS Cognito, providing support for managing JWT tokens on the server-side API. The module is built with security in mind, minimizing the exposure of sensitive tokens to the frontend.

## Key Features

- **AWS Cognito Integration**: Easily connect to AWS Cognito for user authentication and session management.
- **Secure JWT Management**: The module securely stores all three tokens (Access, ID, Refresh) returned by AWS Cognito in a server-side repository, inaccessible to the frontend client. Except IdToken.
- **ID Token Handling**: To enhance security, only the JWT ID Token is sent to the frontend, while the Access Token is kept server-side, protecting access to AWS resources.
- **Refresh Token Support**: The module automatically handles token refreshing. When a token expires, the first request after expiration is processed, and a new token is returned in the `X-Refresh-Token-Updated` header. The client can
seamlessly update the ID Token without the need to manually refresh or handle errors due to token expiration.
- **flow control**: the response from the API provides a list of form windows that should be active in the current session state.

The module provides the following endpoints:

/cognito/register

/cognito/confirm-registration

/cognito/signin

/cognito/signinsession

/cognito/userinfo

/cognito/enablemfa

/cognito/addphonenumber

/cognito/addemail

/cognito/verifyproperty

/cognito/disablemfa

/cognito/signout

/cognito/initiate-password-reset

/cognito/confirm-password-reset

/cognito/change-password

## Installation

Install the package via npm:

```bash
npm install @vizmedia/cognito-nest-api


## Usage

```typescript
...
import { CognitoModule } from '@vizmedia/cognito-nest-api';

@Module({
  imports: [
  VizCognitoModule.forRoot({
      region: process.env.REGION,
      userPoolId: process.env.COGNITO_USER_POOL_ID,
      clientId: process.env.COGNITO_USER_POOL_CLIENT_ID,
      identityPoolId: process.env.COGNITO_IDENTITY_POOL_ID,
      clientSecret: process.env.COGNITO_USER_POOL_CLIENT_SECRET,
      dbConfig: {
        type: "mongodb",
        host: process.env.DB_HOST,
        //port: parseInt(process.env.DB_PORT, 10),
        port: 3010,
        username: process.env.DB_USERNAME,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_DATABASE,
      },
    }),
    ...
    ],
})
export class AppModule {}
```

