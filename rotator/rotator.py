# SPDX-License-Identifier: Apache-2.0

import boto3
import json
import logging
import os
import requests
import urllib.parse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handle(event, context):
  """Secrets Manager Auth0 Client Credentials Rotator

  This handler uses the Auth0 facade to rotate a client's secret. This rotation scheme contacts
  the Auth0 facade as the client itself and sets is own secret, immediately invalidating the
  client's previous secret.

  The Secret SecretString is expected to ba a JSON string with the following format:
  {
    "id": <required, the Auth0 Client ID>,
    "secret": <required, the Auth0 Client Secret>
  }

  Args:
    event (dict): Lambda dictionary of event parameters. These keys must include the following:
      - SecretId: The secret ARN or identifier
      - ClientRequestToken: The ClientRequestToken of the secret version
      - Step: The rotation step (one of "createSecret", "setSecret", "testSecret", or "finishSecret")

    context: (LambdaContext): The Lambda runtime information

  Raises:
    ResourceNotFoundException: If the secret with the specified ARN and stage does not exist

    ValueError: If the secret is not properly configured for rotation

    KeyError: If the secret JSON does not contain the expected keys

  """
  arn = event['SecretId']
  token = event['ClientRequestToken']
  step = event['Step']

  # Set up the client
  service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

  # Make sure that the version is staged correctly
  metadata = service_client.describe_secret(SecretId=arn)
  if 'RotationEnabled' in metadata and not metadata['RotationEnabled']:
    logger.error(f'Secret {arn} is not enabled for rotation.')
    raise ValueError(f'Secret {arn} is not enabled for rotation.')
  versions = metadata['VersionIdsToStages']
  if token not in versions:
    logger.error(f'Secret version {token} has no stage for rotation of secret {arn}.')
    raise ValueError(f'Secret version {token} has no stage for rotation of secret {arn}.')
  if 'AWSCURRENT' in versions[token]:
    logger.info(f'Secret version {token} is already set as AWSCURRENT for secret {arn}.')
    return
  elif 'AWSPENDING' not in versions[token]:
    logger.error(f'Secret version {token} is not set as AWSPENDING for rotation of secret {arn}.')
    raise ValueError(f'Secret version {token} is not set as AWSPENDING for rotation of secret {arn}.')

  # Call the appropriate step
  if step == 'createSecret':
    create_secret(service_client, arn, token)
  elif step == 'setSecret':
    set_secret(service_client, arn, token)
  elif step == 'testSecret':
    test_secret(service_client, arn, token)
  elif step == 'finishSecret':
    finish_secret(service_client, arn, token)
  else:
    logger.error(f'lambda_handler: Invalid step parameter {step} for secret {arn}.')
    raise ValueError(f'lambda_handler: Invalid step parameter {step} for secret {arn}.')


def create_secret(service_client, arn, token):
  """Generate a new secret

  This method first cheks for the existence of a secret for the passed-in token. If one does not exist, it will generate a
  new secret and put is with the passed-in token.

  Args:
    service_client (client): The secrets manager service client

    arn (string): The secret ARN or other identifier

    token (string): The ClientRequestToken associated with the secret version

  Raises:
    ValueError: if the current secret is not valid JSON

    KeyError: if the secret JSON does not contain the expected keys

  """
  # Make sure the current secret exists
  current_dict = get_secret_dict(service_client, arn, 'AWSCURRENT')

  # Now try to get the secret version. If that fails, put a new secret
  try:
    get_secret_dict(service_client, arn, 'AWSPENDING', token)
    logger.info(f'create_secret: Successfully retrieved secret for {arn}.')
  except service_client.exceptions.ResourceNotFoundException:
    # Generate a random client secret (Seems to be [a-zA-Z0-9\-_].)
    client_secret = service_client.get_random_password(PasswordLength=64, ExcludeCharacters='!"#$%&\'()*+,./:;<=>?@[\\]^`{|}~')
    current_dict['secret'] = client_secret['RandomPassword']

    # Put the secret
    service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
    logger.info(f'createSecret: Successfully put secret for ARN {arn} and version {token}.')


def set_secret(service_client, arn, token):
  """Set the pending secret in Auth0

  This method tries to create an access token with the AWSPENDING secret and returns on success. If that fails, it
  tries to log in  with the AWSCURRENT and AWSPREVIOUS secrets. If either one succeeds, if sets the AWSPENDING secret
  as the client secret in Auth0. Otherwise, it raises a ValueError.

  Args:
    service_client (client): The secrets manager service client

    arn (string): The secret ARN or other identifier

    token (string): The ClientRequestToken associated with the secret version

  Raises:
    ResourceNotFoundException: If the secret with the specified ARN and stage does not exist

    ValueError: If the secret is not valid JSON or valid credentials are found to log in to the database

    KeyError: If the secret JSON does not contain the expected keys

  """
  # First try to create an access token with the pending secret. If it succeeds, return
  pending_dict = get_secret_dict(service_client, arn, 'AWSPENDING', token)
  access_token = get_access_token(pending_dict)
  if access_token:
    logger.info(f'set_secret: AWSPENDING secret is already set as client secret in Auth0 for secret {arn}.')
    return

  # Now try the current password
  access_token = get_access_token(get_secret_dict(service_client, arn, 'AWSCURRENT'))
  if not access_token:
    # If both current and pending do not work, try previous
    try:
      access_token = get_access_token(get_secret_dict(service_client, arn, 'AWSPREVIOUS'))
    except service_client.exceptions.ResourceNotFoundException:
      access_token = None

  # If we still don't have an access token, complain bitterly
  if not access_token:
    logger.error(f'set_secret: Unable to acquire access token with previous, current, or pending secret of secret arn {arn}!')
    raise ValueError(f'set_secret: Unable to acquire access token with previous, current, or pending secret of secret arn {arn}!')

  # Now set the client secret to the pending client secret
  set_client_secret(pending_dict, access_token)


def test_secret(service_client, arn, token):
  """Test the pending secret against Auth0

  This method tries to acquire an access token with the secrets staged with AWSPENDING.

  Args:
      service_client (client): The secrets manager service client

      arn (string): The secret ARN or other identifier

      token (string): The ClientRequestToken associated with the secret version

  Raises:
      ResourceNotFoundException: If the secret with the specified arn and stage does not exist

      ValueError: If the secret is not valid JSON or valid credentials are not found to acquire an access token

      KeyError: If the secret json does not contain the expected keys

  """
  # Try to acquire an acccess token with the pending secret
  access_token = get_access_token(get_secret_dict(service_client, arn, 'AWSPENDING', token))
  if not access_token:
    logger.error(f'test_secret: Unable to acquire access token with pending secret of secret ARN {arn}.')
    raise ValueError(f'test_secret: Unable to acquire access token with pending secret of secret ARN {arn}.')


def finish_secret(service_client, arn, token):
  """Finish the rotation by marking the pending secret as current

  This method finishes the secret rotation by staging the secret staged AWSPENDING with the AWSCURRENT stage.

  Args:
      service_client (client): The secrets manager service client

      arn (string): The secret ARN or other identifier

      token (string): The ClientRequestToken associated with the secret version

  """
  # First describe the secret to get the current version
  metadata = service_client.describe_secret(SecretId=arn)
  current_version = None
  for version in metadata['VersionIdsToStages']:
      if 'AWSCURRENT' in metadata['VersionIdsToStages'][version]:
          if version == token:
            # The correct version is already marked as current, return
            logger.info(f'finishSecret: Version {version} already marked as AWSCURRENT for {arn}.')
            return
          current_version = version
          break

  # Finalize by staging the secret version current
  service_client.update_secret_version_stage(SecretId=arn, VersionStage='AWSCURRENT', MoveToVersionId=token, RemoveFromVersionId=current_version)
  logger.info(f'finish_secret: Successfully set AWSCURRENT stage to version {token} for secret {arn}.')


def get_access_token(secret_dict):
  """Gets an Auth0 access token from a secret dictionary

  This helper function tries to retrieve an access token grabbing credential info
  from the secret dictionary. If successful, it returns the access token, otherwise None.

  Args:
    secret_dict (dict): The secret dictionary

  Returns:
    AccessToken: The access token value if successful, otherwise None.

  Raises:
    KeyError: If the secret JSON does not contain the expected keys.
  """
  payload = {
    'client_id': secret_dict['id'],
    'client_secret': secret_dict['secret'],
    'grant_type': 'client_credentials',
    'audience': os.environ['AUDIENCE']
  }
  headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
  }
  url = urllib.parse.urljoin(os.environ['AUTHORITY'], '/oauth/token')
  response = requests.post(url, headers=headers, json=payload).json()
  return response.get('access_token', None)


def set_client_secret(secret_dict, access_token):
  """Sets an Auth0 access token from a secret dictionary

  This helper function sets the client secret
  """
  payload = {
    'client_secret': secret_dict['secret']
  }
  headers = {
    'Accept': 'application/json',
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
  }
  # todo(cosborn) It would be ideal to use the Management API, but I can't get that audience via client_credentials.
  url = urllib.parse.urljoin('https://auth0.cimpress.io/v1/clients/', secret_dict['id'])
  response = requests.patch(url, headers=headers, json=payload)
  response.raise_for_status()
  pass


def get_secret_dict(service_client, arn, stage, token=None):
  """Gets the secret dictionary corresponding to the secret arn, stage, and token

  This helper function gets client credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

  Args:
    service_client (client): The secrets manager service client

    arn (string): The secret ARN or other identifier

    token (string): the ClientRequestToken associated with the secret version, or None if no validation is desired

  Returns:
    SecretDictionary: Secret dictionary

  Raises:
    ResourceNotFoundException: If the secret with the specified ARN and stage does not exist

    Value Error: If the secret is not valid JSON

  """
  required_fields = ['id', 'secret']

  # Only do VersionId validation against the stage if a token is passed in
  if token:
    secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
  else:
    secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
  plaintext = secret['SecretString']
  secret_dict = json.loads(plaintext)

  # Run validations against the secret
  for field in required_fields:
    if field not in secret_dict:
      raise KeyError(f'{field} key is missing from secret JSON')

  return secret_dict
