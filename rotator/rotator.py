# SPDX-License-Identifier: Apache-2.0

import boto3
import json
import logging
import os
import requests
import urllib.parse


# Client Secrets may include "numbers, letters and _, -, +, =, . symbols"
EXCLUDE_CHARACTERS = r'''!"#$%&'()*,/:;<>?@[\]^`{|}~'''


# Set up the dependencies
logger = logging.getLogger()
service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])


def handle(event, context):
  """Secrets Manager Client Secret Rotator

  This handler uses the Auth0 facade to rotate a client's secret. This rotation scheme contacts
  the Auth0 facade as the client itself and sets is own secret, immediately invalidating the
  client's previous secret.

  The Secret SecretString is expected to ba a JSON string with the following format:
  {
    "id": <required, the OAuth2 Client ID>,
    "secret": <required, the OAuth2 Client Secret>
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

  # Make sure that the version is staged correctly
  metadata = service_client.describe_secret(SecretId=arn)
  if 'RotationEnabled' in metadata and not metadata['RotationEnabled']:
    raise ValueError(f'Secret {arn} is not enabled for rotation.')
  versions = metadata['VersionIdsToStages']
  if token not in versions:
    raise ValueError(f'Secret version {token} has no stage for rotation of secret {arn}.')
  if 'AWSCURRENT' in versions[token]:
    logger.info(f'Secret version {token} is already set as AWSCURRENT for secret {arn}.')
    return
  elif 'AWSPENDING' not in versions[token]:
    raise ValueError(f'Secret version {token} is not set as AWSPENDING for rotation of secret {arn}.')

  # Call the appropriate step
  if step == 'createSecret':
    create_secret(arn, token)
  elif step == 'setSecret':
    set_secret(arn, token)
  elif step == 'testSecret':
    test_secret(arn, token)
  elif step == 'finishSecret':
    finish_secret(arn, token)
  else:
    raise ValueError(f'handle: Invalid step parameter {step} for secret {arn}.')


def create_secret(arn, token):
  """Generate a new secret

  This method first checks for the existence of a secret for the passed-in token. If one does not exist, it will generate a
  new secret and put is with the passed-in token.

  Args:
    arn (string): The secret ARN or other identifier

    token (string): The ClientRequestToken associated with the secret version

  Raises:
    ValueError: if the current secret is not valid JSON

    KeyError: if the secret JSON does not contain the expected keys

  """
  # Make sure the current secret exists
  current_dict = get_secret_dict(arn, 'AWSCURRENT')

  # Now try to get the secret version. If that fails, put a new secret
  try:
    get_secret_dict(arn, 'AWSPENDING', token)
    logger.info(f'create_secret: Successfully retrieved secret for {arn}.')
  except service_client.exceptions.ResourceNotFoundException:
    # Generate a random client secret according to length recommendations and allowed character set
    client_secret = service_client.get_random_password(PasswordLength=64, ExcludeCharacters=EXCLUDE_CHARACTERS)
    current_dict['secret'] = client_secret['RandomPassword']

    # Put the secret
    service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
    logger.info(f'create_secret: Successfully put secret for ARN {arn} and version {token}.')


def set_secret(arn, token):
  """Set the pending secret as the client secret

  This method tries to create an access token with the AWSPENDING secret and returns on success. If that fails, it
  tries again with the AWSCURRENT and AWSPREVIOUS secrets. If either one succeeds, it sets the AWSPENDING secret
  as the client secret. Otherwise, it raises a ValueError.

  Args:
    arn (string): The secret ARN or other identifier

    token (string): The ClientRequestToken associated with the secret version

  Raises:
    ResourceNotFoundException: If the secret with the specified ARN and stage does not exist

    ValueError: If the secret is not valid JSON or valid credentials are not found to acquire an access token

    KeyError: If the secret JSON does not contain the expected keys

  """
  # First try to create an access token with the pending secret. If it succeeds, return
  pending_dict = get_secret_dict(arn, 'AWSPENDING', token)
  access_token = create_access_token(pending_dict)
  if access_token:
    logger.info(f'set_secret: AWSPENDING secret is already set as client secret for secret {arn}.')
    return

  # Now try the current secret
  access_token = create_access_token(get_secret_dict(arn, 'AWSCURRENT'))
  if not access_token:
    # If both current and pending do not work, try previous
    try:
      access_token = create_access_token(get_secret_dict(arn, 'AWSPREVIOUS'))
    except service_client.exceptions.ResourceNotFoundException:
      access_token = None

  # If we still don't have an access token, complain bitterly
  if not access_token:
    raise ValueError(f'set_secret: Unable to acquire access token with previous, current, or pending secret of secret arn {arn}!')

  # Now set the client secret to the pending client secret
  set_client_secret(pending_dict, access_token)


def test_secret(arn, token):
  """Test the pending secret by creating an access token

  This method tries to acquire an access token with the secrets staged with AWSPENDING.

  Args:
      arn (string): The secret ARN or other identifier

      token (string): The ClientRequestToken associated with the secret version

  Raises:
      ResourceNotFoundException: If the secret with the specified arn and stage does not exist

      ValueError: If the secret is not valid JSON or valid credentials are not found to acquire an access token

      KeyError: If the secret json does not contain the expected keys

  """
  # Try to acquire an acccess token with the pending secret
  access_token = create_access_token(get_secret_dict(arn, 'AWSPENDING', token))
  if not access_token:
    raise ValueError(f'test_secret: Unable to acquire access token with pending secret of secret ARN {arn}.')


def finish_secret(arn, token):
  """Finish the rotation by marking the pending secret as current

  This method finishes the secret rotation by staging the secret staged AWSPENDING with the AWSCURRENT stage.

  Args:
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


def create_access_token(secret_dict):
  """Creates an access token from a secret dictionary

  This helper function tries to create an access token grabbing credential info
  from the secret dictionary. If successful, it returns the access token, otherwise None.

  Args:
    secret_dict (dict): The secret dictionary

  Returns:
    AccessToken: The access token value if successful, otherwise None.

  Raises:
    KeyError: If the secret JSON does not contain the expected keys.

    KeyError: If the configuration JSON does not contain the expected keys.

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

  configuration = get_openid_configuration()
  response = requests.post(configuration['token_endpoint'], headers=headers, json=payload).json()
  return response.get('access_token', None)


def get_openid_configuration():
  """Gets the OpenID configuration for an authority

  This helper function retrieves the OpenID configuration from the well-known address.
  This configuration includes the endpoint at which client_credentials flows can
  be performed.

  Returns:
    Configuration: The OpenID configuration for the configured authority.

  """
  headers = {
    'Accept': 'application/json'
  }

  url = urllib.parse.urljoin(os.environ['AUTHORITY'], '/.well-known/openid-configuration')
  return requests.get(url, headers=headers).json()


def set_client_secret(secret_dict, access_token):
  """Sets an client secret from a secret dictionary

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

  # todo(cosborn)
  # It would be ideal to use the Auth0 Management API, but they lack robust permissions --
  # I'd be able to rotate anybody's secret.
  url = urllib.parse.urljoin('https://auth0.cimpress.io/v1/clients/', secret_dict['id'])
  response = requests.patch(url, headers=headers, json=payload)
  response.raise_for_status()


def get_secret_dict(arn, stage, token=None):
  """Gets the secret dictionary corresponding to the secret arn, stage, and token

  This helper function gets client credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

  Args:
    arn (string): The secret ARN or other identifier

    token (string): the ClientRequestToken associated with the secret version, or None if no validation is desired

  Returns:
    SecretDictionary: Secret dictionary

  Raises:
    ResourceNotFoundException: If the secret with the specified ARN and stage does not exist

    ValueError: If the secret is not valid JSON

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
