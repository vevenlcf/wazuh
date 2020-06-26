# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import concurrent.futures
import copy
import logging
import os
from secrets import token_urlsafe
from shutil import chown
from time import time

from jose import JWTError, jwt
from werkzeug.exceptions import Unauthorized

from api.api_exception import APIException
from api.configuration import security_conf
from api.constants import SECURITY_PATH
from api.util import raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.rbac.orm import AuthenticationManager, TokenManager

pool = concurrent.futures.ThreadPoolExecutor()


def check_user_master(user, password):
    """This function must be executed in master node.

    Parameters
    ----------
    user : str
        Unique username
    password : str
        User password

    Returns
    -------
    Dict with the result of the query
    """
    with AuthenticationManager() as auth_:
        if auth_.check_user(user, password):
            return {'result': True}

    return {'result': False}


def check_user(user, password, required_scopes=None):
    """Convenience method to use in OpenAPI specification

    Parameters
    ----------
    user : str
        Unique username
    password : str
        User password
    required_scopes

    Returns
    -------
    Dict with the username and his status
    """
    dapi = DistributedAPI(f=check_user_master,
                          f_kwargs={'user': user, 'password': password},
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=True,
                          logger=logging.getLogger('wazuh')
                          )
    data = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result())

    if data['result']:
        return {'sub': user,
                'active': True
                }


# Set JWT settings
JWT_ISSUER = 'wazuh'
JWT_ALGORITHM = 'HS256'
_secret_file_path = os.path.join(SECURITY_PATH, 'jwt_secret')


def generate_secret():
    """Generate secret file to keep safe or load existing secret."""
    try:
        if not os.path.exists(_secret_file_path):
            jwt_secret = token_urlsafe(512)
            with open(_secret_file_path, mode='x') as secret_file:
                secret_file.write(jwt_secret)
            try:
                chown(_secret_file_path, 'ossec', 'ossec')
            except PermissionError:
                pass
            os.chmod(_secret_file_path, 0o640)
        else:
            with open(_secret_file_path, mode='r') as secret_file:
                jwt_secret = secret_file.readline()
    except IOError:
        raise APIException(2002)

    return jwt_secret


def change_secret():
    """Generate new JWT secret."""
    new_secret = token_urlsafe(512)
    with open(_secret_file_path, mode='w') as jwt_secret:
        jwt_secret.write(new_secret)


def get_security_conf():
    return copy.deepcopy(security_conf)


def generate_token(user_id=None, rbac_policies=None):
    """Generate an encoded jwt token. This method should be called once a user is properly logged on.

    Parameters
    ----------
    user_id : str
        Unique username
    rbac_policies : dict
        Permissions for the user

    Returns
    -------
    JWT encode token
    """
    dapi = DistributedAPI(f=get_security_conf,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=True,
                          logger=logging.getLogger('wazuh')
                          )
    result = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result()).values()
    token_exp, rbac_mode = list(result)
    timestamp = int(time())
    rbac_policies['rbac_mode'] = rbac_mode
    payload = {
        "iss": JWT_ISSUER,
        "iat": int(timestamp),
        "exp": int(timestamp + token_exp),
        "sub": str(user_id),
        "rbac_policies": rbac_policies
    }

    return jwt.encode(payload, generate_secret(), algorithm=JWT_ALGORITHM)


def check_token(username, token_iat_time):
    """Check the validity of a token with the current time and the generation time of the token.

    Parameters
    ----------
    username : str
        Unique username
    token_iat_time : int
        Issued at time of the current token
    Returns
    -------
    Dict with the result
    """
    with TokenManager() as tm:
        result = tm.is_token_valid(username=username, token_iat_time=int(token_iat_time))

    return {'valid': result}


def decode_token(token):
    """Decode a jwt formatted token. Raise an Unauthorized exception in case validation fails.

    Parameters
    ----------
    token : str
        JWT formatted token

    Returns
    -------
    Dict payload ot the token
    """
    try:
        payload = jwt.decode(token, generate_secret(), algorithms=[JWT_ALGORITHM])
        dapi = DistributedAPI(f=check_token,
                              f_kwargs={'username': payload['sub'], 'token_iat_time': payload['iat']},
                              request_type='local_master',
                              is_async=False,
                              wait_for_complete=True,
                              logger=logging.getLogger('wazuh')
                              )
        data = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result())

        if not data.to_dict()['result']['valid']:
            raise Unauthorized

        dapi = DistributedAPI(f=get_security_conf,
                              request_type='local_master',
                              is_async=False,
                              wait_for_complete=True,
                              logger=logging.getLogger('wazuh')
                              )
        result = raise_if_exc(pool.submit(asyncio.run, dapi.distribute_function()).result())
        current_rbac_mode = result['rbac_mode']
        current_expiration_time = result['auth_token_exp_timeout']
        if payload['rbac_policies']['rbac_mode'] != current_rbac_mode or \
                (payload['exp'] - payload['iat']) != current_expiration_time:
            raise Unauthorized

        return payload
    except JWTError as e:
        raise Unauthorized from e
