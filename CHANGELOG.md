## Version 1.1.4 (Released 2020-02-10)

- An error related to exception handling has been corrected.
- The JSON structure of the generated secret has been improved.

## Version 1.1.0 (Released 2020-01-14)

- The permission to allow Secrets Manager to invoke the rotation Lambda have been moved into the application.
  - This requires a new capability acknowledgement: `CAPABILITY_RESOURCE_POLICY`.
- The rotator can rotate secrets encrypted by a customer-managed KMS key.

## Version 1.0.2 (Released 2019-11-25)

- The runtime has been updated to `python3.8`.

## Version 1.0.1 (Released 2019-11-20)

- A slight performance improvement related to the eager creation of an AWS service client.

## Version 1.0.0 (Released 2019-11-01)

- Everything is new!
