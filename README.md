# Client Secret Rotation

## What It Is

The Platform Client Secret Rotator is an AWS Secrets Manager [Lambda Function Rotator][] intended to be used with AWS Secrets Manager and Auth0. Secrets Manager can use rotators implemented as Lambda Functions to securely and automatically rotate secret configuration values. This rotator is confugred out of the box for use with the Cimpress Mass Customization Platform.

[Lambda Function Rotator]: https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html

## Why You Want It

For good security hygiene, secret values should be rotated regularly. But _it's a pain_. And once the secret value is rotated wherever it's stored, how can that be injected into the application which requires the value? This is the value propsition of AWS Secrets Manager, and that value is augmented by the ability to write custom rotators. With this rotator configured to rotate a secret, the client secret will never be stale and it will never be out of date. You should configure your application to retrieve the secret just-in-time at runtime. Provide the ARN of the secret via some configuration means (though setting an environment variable in CloudFormation is probably best), and no further configuration is required, either before or after rotation.

## How To Use It

Here's an example use, provided in AWS Cloudformation:

```yaml
# TODO
```

## Helpful Links

* [AWS Secrets Manager][]
* [Auth0 Client Secret][]

[AWS Secrets Manager]: https://aws.amazon.com/secrets-manager/
[Auth0 Client Secret]: https://auth0.com/docs/applications/concepts/client-secret
