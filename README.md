# Client Secret Rotation

[![Find it on the Serverless Application Repository][logo]][sam]

[logo]: https://img.shields.io/badge/SAM-Find%20it%20on%20the%20Serverless%20Application%20Repository-brightgreen
[sam]: https://serverlessrepo.aws.amazon.com/applications/arn:aws:serverlessrepo:us-east-1:820870426321:applications~platform-client-secret-rotator

Find [step-by-step installation and setup instructions][] on the wiki!

[step-by-step installation and setup instructions]: https://github.com/Cimpress-MCP/Platform-Client-Secret-Rotator/wiki/Step-by-Step-Setup

## What It Is

The Platform Client Secret Rotator is an AWS Secrets Manager [Lambda Function Rotator][] intended to be used with AWS Secrets Manager and Auth0. Secrets Manager can use rotators implemented as Lambda Functions to securely and automatically rotate secret configuration values. This rotator is configured out of the box for use with the Cimpress Mass Customization Platform.

[Lambda Function Rotator]: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html

## Why You Want It

For good security hygiene, secret values should be rotated regularly. But _it's a pain_. And once the secret value is rotated wherever it's stored, how can that be injected into the application which requires the value? This is the value propsition of AWS Secrets Manager, and that value is augmented by the ability to write custom rotators. With this rotator configured to rotate a secret, the client secret will never be stale and it will never be out of date. You should configure your application to retrieve the secret just-in-time at runtime. Provide the ARN of the secret via some configuration means (though setting an environment variable in CloudFormation is probably best), and no further configuration is required, either before or after rotation.

## How To Use It

Here's an example use, provided in AWS Cloudformation:

```yaml
# snip

Transform: AWS::Serverless-2016-10-31

# snip
Resources:
  ExampleSecretRotator:
    Type: AWS::Serverless::Application
    Properties:
      Location:
        ApplicationId: arn:aws:serverlessrepo:us-east-1:820870426321:applications/platform-client-secret-rotator
        SemanticVersion: 1.1.4
      Parameters:
        Endpoint: !Sub https://secretsmanager.${AWS::Region}.${AWS::URLSuffix}
        FunctionName: !Sub ${AWS::StackName}-client-credentials-secret-rotator
        KmsKeyArn: !GetAtt EncryptionKey.Arn
  ExampleSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: An example client ID and secret.
      GenerateSecretString:
        SecretStringTemplate: |-
          { "id": "<<client_id>>" }
        GenerateStringKey: secret
        PasswordLength: 64
        ExcludeCharacters: |-
          !"#$%&'()*,/:;<>?@[\]^`{|}~
      KmsKeyId: !Ref EncryptionKey
  ExampleSecretRotationSchedule:
    Type: AWS::SecretsManager::RotationSchedule
    Properties:
      RotationLambdaARN: !GetAtt ExampleSecretRotator.Outputs.RotationLambdaARN
      RotationRules:
        AutomaticallyAfterDays: 30
      SecretId: !Ref ExampleSecret
# snip
```

### Bootstrapping

There is an unavoidable bootstrapping step when deploying the Platform Client Secret Rotator into a service for the first time. The deployment process has no way of knowing what a client's _current_ secret is (nor should it!), so the first rotation which occurs after deployment will necessarily fail. To take ownership of the rotation of a client secret, transfer the client secret value into AWS Secrets Manager (into the deployed secret, specifically -- see `ExampleSecret` above) and instruct AWS Secrets Manager to rotate the secret immediately. It's hands-off operation from then on out.

<!-- It's possible to transfer the secret value earlier, catching the secret in the state between when it is deployed and the rotator is deployed, but why accumulate that much stress in your life? -->

## Helpful Links

* [AWS Secrets Manager][]
* [Auth0 Client Secret][]

[AWS Secrets Manager]: https://aws.amazon.com/secrets-manager/
[Auth0 Client Secret]: https://auth0.com/docs/applications/concepts/client-secret

## Inspirations

* AWS's [Rotation Lambda Functions][] for RDS credentials
* The CloudFormation [Custom Resource Helper][] library

[Rotation Lambda Functions]: https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas
[Custom Resource Helper]: https://github.com/aws-cloudformation/custom-resource-helper
