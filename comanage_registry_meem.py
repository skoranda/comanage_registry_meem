"""
SATOSA microservice that coordinates MFA enrollment and exemption working
in conjunction with the COmanage Registry MeemEnroller Plugin. See
https://spaces.at.internet2.edu/display/COmanage/MeemEnroller+Plugin

This microservice assumes the LDAP Attribute Store microservice is
available, configured, and has run before this microservice. The LDAP
Attribute Store microservice should be configured to write the authenticated
user's group memberships into a SATOSA internal attribute
(e.g., i_is_member_of) so that this microservice can inspect the attribute
values (list of group memberships) to determine if the user is in the
configured MFA exempt group.

A typical configuration would be

module: comanage_registry_meem.ComanageRegistryMeem
name: ComanageRegistryMeem
config:
  default:

      display_name:
          # SATOSA internal attribute name to use
          internal_attribute_name: i_idpdisplayname
          # Language preference with 'en' or English as default
          lang: en
      entity_id:
          internal_attribute_name: i_idpentityid
      organization_name:
          internal_attribute_name: i_idporgname
          lang: en
      organization_display_name:
          internal_attribute_name: i_idporgdisplayname
          lang: en
"""

import copy
import functools
import json
import logging

from base64 import b64encode
from pprint import pformat
from requests import ConnectionError, Session, Timeout
from time import mktime, strptime, time
from urllib.parse import urlencode, urlparse, urlunparse

import satosa.logging_util as lu
from satosa.exception import SATOSAError
from satosa.internal import InternalData
from satosa.micro_services.base import ResponseMicroService
from satosa.response import Redirect
from satosa.state import cookie_to_state, state_to_cookie

logger = logging.getLogger(__name__)


class MeemMfaStatusUnknown(SATOSAError):
    """
    User MFA status from COmanage Registry MeemEnroller API is unknown.
    """


class ComanageRegistryMeem(ResponseMicroService):
    """
    """
    config_defaults = {
        "group_membership_attribute": "i_is_member_of",
    }

    def __init__(self, config, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if "default" not in config:
            msg = "No default configuration is present"
            logger.error(msg)
            raise SATOSAError(msg)

        self.config = {}

        # Process the default configuration first then any per-SP overrides.
        sp_list = ["default"]
        sp_list.extend([key for key in config.keys() if key != "default"])

        for sp in sp_list:
            if not isinstance(config[sp], dict):
                msg = "Configuration value for {} must be a dictionary"
                logger.error(msg)
                raise SATOSAError(msg)

            # Initialize configuration using module defaults then update
            # with configuration defaults and then per-SP overrides.
            sp_config = copy.deepcopy(self.config_defaults)
            if "default" in self.config:
                sp_config.update(self.config["default"])
            sp_config.update(config[sp])

            sp_config = json.loads(
                json.dumps(sp_config)
                .replace("<base_url>", self.base_url)
                .replace("<name>", self.name)
            )

            self.config[sp] = sp_config

        msg = "ComanageRegistryMeem microservice initialized"
        logger.info(msg)

    def handle_meem_reminder_return(self, context):
        """
        """
        config = self.config['default']
        cookie_name = config.get('cookie_state_name', "SATOSA_MEEM_STATE")
        state_encryption_key = config.get('state_encryption_key')
        state = cookie_to_state(context.cookie, cookie_name,
                                state_encryption_key)

        context.state = state
        internal_data = context.state[self.name]["internal_data"]
        data = InternalData.from_dict(internal_data)
        session_id = lu.get_session_id(state)
        attributes = data.attributes
        msg = "MEEM reminder return with attributes {}".format(attributes)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.info(logline)

        user_mfa_exempt = context.state[self.name].get("user_mfa_exempt", None)

        if not user_mfa_exempt:
            msg = "User MFA exempt status is false or missing"
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.error(logline)
            raise SATOSAError(msg)

        msg = "User is MFA exempt so continuing to SP with no MFA"
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.info(logline)

        context.decorate("user_mfa_exempt", True)

        return super().process(context, data)

    def handle_token_enrollment_return(self, context):
        """
        """
        config = self.config['default']
        cookie_name = config.get('cookie_state_name', "SATOSA_MEEM_STATE")
        state_encryption_key = config.get('state_encryption_key')
        state = cookie_to_state(context.cookie, cookie_name,
                                state_encryption_key)
        session_id = lu.get_session_id(state)

        # TODO clear the cookie...

        context.state = state
        msg = "Loaded state {state} from cookie {cookie}"
        msg = msg.format(state=state, cookie=context.cookie)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)

        internal_data = context.state[self.name]["internal_data"]
        data = InternalData.from_dict(internal_data)
        attributes = data.attributes

        logger.debug(data)
        logger.debug(attributes)

        # Let the setup microservice determine if there needs to be a
        # step up.

        return super().process(context, data)

    def process(self, context, data):
        """
        """
        state = context.state
        session_id = lu.get_session_id(state)
        attributes = data.attributes

        requester = data.requester
        issuer = data.auth_info.issuer

        entity_ids = [requester, issuer, "default"]

        config, entity_id = next((self.config.get(e), e)
                                 for e in entity_ids if self.config.get(e))

        msg = {
            "message": "entityID for the involved entities",
            "requester": requester,
            "issuer": issuer,
            "config": config,
        }
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)

        # Ignore this entityID entirely if so configured.
        if config.get("ignore", False):
            msg = "Ignoring entityID {}".format(entity_id)
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.info(logline)
            return super().process(context, data)

        # Determine if user is exempt from MFA
        mfa_exempt_group = config['mfa_exempt_group']
        msg = "MFA exempt group is '{}'".format(mfa_exempt_group)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)

        user_groups = attributes.get(config['group_membership_attribute'], [])
        msg = "User groups are {}".format(user_groups)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)

        user_mfa_exempt = True if mfa_exempt_group in user_groups else False

        if user_mfa_exempt:
            msg = "User is MFA exempt"
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.info(logline)

            identifier_type = config['mfa_status_query_identifier_type']
            identifiers = attributes.get(identifier_type, [None])
            identifier = identifiers.pop()

            if not identifier:
                # TODO Handle this appropriately
                pass

            # TODO Need to try/catch here and redirect (fail closed)
            # if we cannot get the MFA status...
            meem_enroller_id, mfa_exempt_time = self.query_mfa_status(
                                                    config,
                                                    identifier,
                                                    session_id)

            logger.debug("meem_enroller_id is {}".format(meem_enroller_id))
            logger.debug("mfa_exempt_time is {}".format(mfa_exempt_time))

            context.state[self.name] = {
                "user_mfa_exempt": True,
                "internal_data": data.to_dict(),
            }

            cookie_name = config.get('cookie_state_name', "SATOSA_MEEM_STATE")
            state_encryption_key = config.get('state_encryption_key')
            cookie = state_to_cookie(context.state, cookie_name, "/",
                                     state_encryption_key)

            headers = cookie.output().split(": ", 1)

            endpoints = config['endpoints']
            meem_reminder_return = endpoints['meem_reminder_return']

            meem_reminder_url = urlparse(config['mfa_status_query_base'])
            path = "registry/meem_enroller/meem_reminders/remind/{}"
            path = path.format(meem_enroller_id)
            meem_reminder_url = meem_reminder_url._replace(path=path)
            query = urlencode({'countdown': mfa_exempt_time,
                               'return': meem_reminder_return})
            meem_reminder_url = meem_reminder_url._replace(query=query)
            meem_reminder_url = urlunparse(meem_reminder_url)
            logger.debug("meem_reminder_url is {}".format(meem_reminder_url))

            redirect = Redirect(meem_reminder_url)
            redirect.headers.append(headers)
            return redirect

        msg = "User is not MFA exempt"
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.info(logline)

        context_class_received = data.auth_info.auth_class_ref
        msg = "Authenticating IdP asserted authentication context {}"
        msg = msg.format(context_class_received)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(msg)

        mfa_context_classes = config.get('mfa_context_class', [])
        if context_class_received in mfa_context_classes:
            # The authenticating IdP asserted MFA so return and let the
            # step up microservice determine the same, resulting in a no-op.
            msg = "Authenticating IdP asserted MFA"
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.info(msg)
            return super().process(context, data)

        msg = "Authenticating IdP did not assert MFA"
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.info(msg)

        # Determine if user has an authenticator registered
        mfa_authenticators = config.get('mfa_authenticators', {})
        for token_type in mfa_authenticators:
            attr = mfa_authenticators[token_type]
            user_authenticators = attributes.get(attr, [])
            if user_authenticators:
                msg = "Found authenticators {} for user"
                msg = msg.format(user_authenticators)
                logline = lu.LOG_FMT.format(id=session_id, message=msg)
                logger.info(msg)

                # User has an authenticator registered so return and let
                # the step up microservice determine if a step up is necessary
                # or not, and if so it will manage it.
                return super().process(context, data)

        # User is not MFA exempt, the authenticating IdP did not assert MFA,
        # and the user does not have any authenticators registered, so
        # redirect the user to go enroll an authenticator.
        # TODO

        context.state[self.name] = {
            "internal_data": data.to_dict(),
        }

        cookie_name = config.get('cookie_state_name', "SATOSA_MEEM_STATE")
        state_encryption_key = config.get('state_encryption_key')
        cookie = state_to_cookie(context.state, cookie_name, "/",
                                 state_encryption_key)

        headers = cookie.output().split(": ", 1)

        endpoints = config['endpoints']
        token_enrollment_return = endpoints['token_enrollment_return']

        mfa_enrollment_flow_url = config.get('mfa_enrollment_flow_url')

        encoded = token_enrollment_return.encode('utf-8')
        altchars = '._'.encode('utf-8')
        b64encoded = b64encode(encoded, altchars)
        token_enrollment_return = b64encoded.decode()
        token_enrollment_return = token_enrollment_return.replace('=', '-')

        url = "{}/return:{}"
        mfa_enrollment_flow_url = url.format(mfa_enrollment_flow_url,
                                             token_enrollment_return)

        msg = "mfa_enrollment_flow_url is {}".format(mfa_enrollment_flow_url)
        logger.debug(msg)

        redirect = Redirect(mfa_enrollment_flow_url)
        redirect.headers.append(headers)

        # TODO clear the main SATOSA session?

        return redirect

    def query_mfa_status(self, config, identifier, session_id):
        meem_rest_api_session = Session()

        api_user = config['mfa_status_query_api_username']
        api_pass = config['mfa_status_query_api_secret']
        meem_rest_api_session.auth = (api_user, api_pass)

        query_base = config['mfa_status_query_base']
        query_base = "{}/registry/meem_enroller/v1/status".format(query_base)

        meem_enroller_id = None
        mfa_exempt_time_seconds = None

        mfa_status = None
        mfa_exempt = None

        meem_enroller_ids = config['mfa_status_query_meem_enroller_ids']

        for enroller_id in meem_enroller_ids:
            url = "{}/{}/{}".format(query_base, enroller_id, identifier)

            # TODO need to try and catch exception here...going on in the
            # loop if can
            query_response = self.query_meem_plugin_api(meem_rest_api_session,
                                                        url, session_id)

            if "mfa_status" not in query_response:
                msg = "Key mfa_status not in query response"
                logline = lu.LOG_FMT.format(id=session_id, message=msg)
                logger.warning(logline)
                continue

            if "mfa_exempt" not in query_response:
                msg = "Key mfa_exempt not in query response"
                logline = lu.LOG_FMT.format(id=session_id, message=msg)
                logger.warning(logline)
                continue

            if not query_response['mfa_status']:
                msg = "No MFA status for MEEM enroller ID {}"
                msg = msg.format(enroller_id)
                logline = lu.LOG_FMT.format(id=session_id, message=msg)
                logger.info(logline)
                continue

            mfa_status = query_response['mfa_status'][0]['MeemMfaStatus']
            mfa_exempt = query_response['mfa_exempt']
            break

        # TODO If mfa_status and/or mfa_exempt are still none throw
        # exception to be caught
        if mfa_status:
            meem_enroller_id = mfa_status['meem_enroller_id']

        if mfa_exempt is False:
            mfa_exempt_time_seconds = 0
        elif isinstance(mfa_exempt, str):
            time_stamp = mktime(strptime(mfa_exempt, "%Y-%m-%d %H:%M:%S"))
            time_now = time()
            mfa_exempt_time_seconds = int(time_stamp - time_now)

        return (meem_enroller_id, mfa_exempt_time_seconds)

    def query_meem_plugin_api(self, meem_rest_api_session, url, session_id):
        try:
            response = meem_rest_api_session.get(url)
        except ConnectionError as e:
            msg = "Connection error querying MeemEnroller REST API: {}"
            msg = msg.format(e)
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.error(logline)
            raise MeemMfaStatusUnknown(msg)
        except Timeout as e:
            msg = "MeemEnroller REST API query timed out: {}".format(e)
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.error(logline)
            raise MeemMfaStatusUnknown(msg)
        except Exception as e:
            msg = "Unexpected error querying MeemEnroller REST API: {}"
            msg = msg.format(e)
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.error(logline)
            raise MeemMfaStatusUnknown(msg)

        if response.status_code == 401:
            msg = "MeemEnroller REST API returned 401"
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.error(logline)
            raise MeemMfaStatusUnknown(msg)

        if response.status_code != 200:
            msg = "MeemEnroller REST API returned unexpected status code {}"
            msg = msg.format(response.status_code)
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.error(logline)
            raise MeemMfaStatusUnknown(msg)

        try:
            query_response = response.json()
        except ValueError as e:
            msg = "Error parsing MeemEnroller response: {}".format(e)
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.error(logline)
            raise MeemMfaStatusUnknown(msg)

        msg = "MeemEnroller response is"
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)

        msg = pformat(query_response)
        logline = lu.LOG_FMT.format(id=session_id, message=msg)
        logger.debug(logline)

        if ("mfa_exempt" not in query_response
                or "mfa_status" not in query_response):
            msg = "Unexpected response from MeemEnroller: {}"
            msg = msg.format(query_response)
            logline = lu.LOG_FMT.format(id=session_id, message=msg)
            logger.error(logline)
            raise MeemMfaStatusUnknown(msg)

        return query_response

    def register_endpoints(self):
        url_map = []

        # Process the default configuration first then any per-SP overrides.
        sp_list = ["default"]
        sp_list.extend([key for key in self.config.keys() if key != "default"])

        for sp in sp_list:
            if not isinstance(self.config[sp], dict):
                msg = "Configuration value for {} must be a dictionary"
                logger.error(msg)
                raise SATOSAError(msg)

            endpoints = self.config[sp]['endpoints']

            meem_reminder_return = endpoints['meem_reminder_return']
            parsed_endp = urlparse(meem_reminder_return)
            url_map.append(
                    (
                        "^{endpoint}$".format(endpoint=parsed_endp.path[1:]),
                        functools.partial(self.handle_meem_reminder_return)
                        )
                    )

            msg = "Registered endpoint {}".format(meem_reminder_return)
            logline = lu.LOG_FMT.format(id=None, message=msg)
            logger.debug(logline)

            token_enrollment_return = endpoints['token_enrollment_return']
            parsed_endp = urlparse(token_enrollment_return)
            url_map.append(
                    (
                        "^{endpoint}$".format(endpoint=parsed_endp.path[1:]),
                        functools.partial(self.handle_token_enrollment_return)
                        )
                    )

            msg = "Registered endpoint {}".format(token_enrollment_return)
            logline = lu.LOG_FMT.format(id=None, message=msg)
            logger.debug(logline)

        return url_map
