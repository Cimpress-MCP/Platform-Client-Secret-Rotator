# SPDX-License-Identifier: Apache-2.0

import boto3
import json
import logging
import os
import requests
import urllib.parse


# Client Secrets may include "numbers, letters and _, -, +, =, . symbols"
EXCLUDE_CHARACTERS = r'''!"#$%&'()*,/:;<>?@[\]^`{|}~'''


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Secrets Manager Rotation Template
    This is a template for creating an AWS Secrets Manager rotation lambda
    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)
        context (LambdaContext): The Lambda runtime information
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not properly configured for rotation
        KeyError: If the event parameters do not contain the expected keys
    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def create_secret(service_client, arn, token):
    """Create the secret
    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
    """
    # Make sure the current secret exists
    service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)

    except service_client.exceptions.ResourceNotFoundException:
        # Generate a random password
        passwd = service_client.get_random_password(ExcludeCharacters=EXCLUDE_CHARACTERS)

        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=passwd['RandomPassword'], VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(service_client, arn, token):
    """Set the secret
    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    # First try to create an access token with the pending secret. If it succeeds, return
    pending_dict = _get_secret_dict(service_client, arn, 'AWSPENDING', token)
    access_token = _create_access_token(pending_dict)
    if access_token:
        logger.info(f'set_secret: AWSPENDING secret is already set as client secret for secret {arn}.')
        return

    # Now try the current secret
    access_token = _create_access_token(_get_secret_dict(service_client, arn, 'AWSCURRENT'))
    if not access_token:
    # If both current and pending do not work, try previous
        try:
            access_token = _create_access_token(_get_secret_dict(service_client, arn, 'AWSPREVIOUS'))

        except service_client.exceptions.ResourceNotFoundException:
            access_token = None

    # If we still don't have an access token, complain bitterly
    if not access_token:
        raise ValueError(f'set_secret: Unable to acquire access token with previous, current, or pending secret of secret arn {arn}!')

    # Now set the client secret to the pending client secret
    _set_client_secret(pending_dict, access_token)


def test_secret(service_client, arn, token):
    """Test the secret
    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
    is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
    all of the expected permissions against the database.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    # Try to acquire an acccess token with the pending secret
    access_token = _create_access_token(_get_secret_dict(service_client, arn, 'AWSPENDING', token))
    if not access_token:
        raise ValueError(f'test_secret: Unable to acquire access token with pending secret of secret ARN {arn}.')


def finish_secret(service_client, arn, token):
    """Finish the secret
    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist
    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))


def _create_access_token(secret_dict):
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

    configuration = _get_openid_configuration()
    response = requests.post(configuration['token_endpoint'], headers=headers, json=payload).json()
    return response.get('access_token', None)


def _get_openid_configuration():
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


def _set_client_secret(secret_dict, access_token):
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


def _get_secret_dict(service_client, arn, stage, token=None):
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
