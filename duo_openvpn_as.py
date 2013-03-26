#!/usr/bin/env python
#
# duo_openvpn_as.py
#
# Copyright 2012 Duo Security, Inc.
# All rights reserved, all wrongs reversed.

# ------------------------------------------------------------------
# Fill in your integration credentials on the following three lines:
IKEY = '<DUO INTEGRATION KEY HERE>'
SKEY = '<DUO INTEGRATION SECRET KEY HERE>'
HOST = '<DUO API HOSTNAME HERE>'

# To use an HTTPS proxy, enter its address below. If PROXY_HOST is
# left blank no proxy will be used.
PROXY_HOST = ''
PROXY_PORT = 8080

# ------------------------------------------------------------------

import syslog
import tempfile
import traceback

from pyovpn.plugin import (SUCCEED, FAIL)

SYNCHRONOUS=False

API_RESULT_AUTH   = 'auth'
API_RESULT_ALLOW  = 'allow'
API_RESULT_DENY   = 'deny'
API_RESULT_ENROLL = 'enroll'

CA_CERT = '''
-----BEGIN CERTIFICATE-----
MIIE2DCCBEGgAwIBAgIEN0rSQzANBgkqhkiG9w0BAQUFADCBwzELMAkGA1UE
BhMCVVMxFDASBgNVBAoTC0VudHJ1c3QubmV0MTswOQYDVQQLEzJ3d3cuZW50
cnVzdC5uZXQvQ1BTIGluY29ycC4gYnkgcmVmLiAobGltaXRzIGxpYWIuKTEl
MCMGA1UECxMcKGMpIDE5OTkgRW50cnVzdC5uZXQgTGltaXRlZDE6MDgGA1UE
AxMxRW50cnVzdC5uZXQgU2VjdXJlIFNlcnZlciBDZXJ0aWZpY2F0aW9uIEF1
dGhvcml0eTAeFw05OTA1MjUxNjA5NDBaFw0xOTA1MjUxNjM5NDBaMIHDMQsw
CQYDVQQGEwJVUzEUMBIGA1UEChMLRW50cnVzdC5uZXQxOzA5BgNVBAsTMnd3
dy5lbnRydXN0Lm5ldC9DUFMgaW5jb3JwLiBieSByZWYuIChsaW1pdHMgbGlh
Yi4pMSUwIwYDVQQLExwoYykgMTk5OSBFbnRydXN0Lm5ldCBMaW1pdGVkMTow
OAYDVQQDEzFFbnRydXN0Lm5ldCBTZWN1cmUgU2VydmVyIENlcnRpZmljYXRp
b24gQXV0aG9yaXR5MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDNKIM0
VBuJ8w+vN5Ex/68xYMmo6LIQaO2f55M28Qpku0f1BBc/I0dNxScZgSYMVHIN
iC3ZH5oSn7yzcdOAGT9HZnuMNSjSuQrfJNqc1lB5gXpa0zf3wkrYKZImZNHk
mGw6AIr1NJtl+O3jEP/9uElY3KDegjlrgbEWGWG5VLbmQwIBA6OCAdcwggHT
MBEGCWCGSAGG+EIBAQQEAwIABzCCARkGA1UdHwSCARAwggEMMIHeoIHboIHY
pIHVMIHSMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRW50cnVzdC5uZXQxOzA5
BgNVBAsTMnd3dy5lbnRydXN0Lm5ldC9DUFMgaW5jb3JwLiBieSByZWYuIChs
aW1pdHMgbGlhYi4pMSUwIwYDVQQLExwoYykgMTk5OSBFbnRydXN0Lm5ldCBM
aW1pdGVkMTowOAYDVQQDEzFFbnRydXN0Lm5ldCBTZWN1cmUgU2VydmVyIENl
cnRpZmljYXRpb24gQXV0aG9yaXR5MQ0wCwYDVQQDEwRDUkwxMCmgJ6AlhiNo
dHRwOi8vd3d3LmVudHJ1c3QubmV0L0NSTC9uZXQxLmNybDArBgNVHRAEJDAi
gA8xOTk5MDUyNTE2MDk0MFqBDzIwMTkwNTI1MTYwOTQwWjALBgNVHQ8EBAMC
AQYwHwYDVR0jBBgwFoAU8BdiE1U9s/8KAGv7UISX8+1i0BowHQYDVR0OBBYE
FPAXYhNVPbP/CgBr+1CEl/PtYtAaMAwGA1UdEwQFMAMBAf8wGQYJKoZIhvZ9
B0EABAwwChsEVjQuMAMCBJAwDQYJKoZIhvcNAQEFBQADgYEAkNwwAvpkdMKn
CqV8IY00F6j7Rw7/JXyNEwr75Ji174z4xRAN95K+8cPV1ZVqBLssziY2Zcgx
xufuP+NXdYR6Ee9GTxj005i7qIcyunL2POI9n9cd2cNgQ4xYDiKWL2KjLB+6
rQXvqzJ4h6BUcxm1XAX5Uj5tLUUL9wqT6u0G+bI=
-----END CERTIFICATE-----
'''

### OpenVPN Access Server imports post-auth scripts into database
### blobs, so we have to include dependencies inline.

### The following code was adapted from duo_client_python.

import base64
import email.utils
import hashlib
import hmac
import json
import os
import sys
import urllib

def canon_params(params):
    args = []
    for key in sorted(params.keys()):
        val = params[key]
        arg = '%s=%s' % (urllib.quote(key, '~'), urllib.quote(val, '~'))
        args.append(arg)
    return '&'.join(args)


def canonicalize(method, host, uri, params, date, sig_version):
    if sig_version == 1:
        canon = []
    elif sig_version == 2:
        canon = [date]
    else:
        raise NotImplementedError(sig_version)

    canon += [
        method.upper(),
        host.lower(),
        uri,
        canon_params(params),
    ]
    return '\n'.join(canon)


def sign(ikey, skey, method, host, uri, date, sig_version, params):
    """
    Return basic authorization header line with a Duo Web API signature.
    """
    canonical = canonicalize(method, host, uri, params, date, sig_version)
    if isinstance(skey, unicode):
        skey = skey.encode('utf-8')
    sig = hmac.new(skey, canonical, hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())
    return 'Basic %s' % base64.b64encode(auth)


def encode_params(params):
    """Returns copy of params with unicode strings utf-8 encoded"""
    new_params = {}
    for key, value in params.items():
        if isinstance(key, unicode):
            key = key.encode("utf-8")
        if isinstance(value, unicode):
            value = value.encode("utf-8")
        new_params[key] = value
    return new_params


class Client(object):
    sig_version = 1

    def __init__(self, ikey, skey, host,
                 ca_certs=None):
        """
        ca - Path to CA pem file.
        """
        self.ikey = ikey
        self.skey = skey
        self.host = host
        self.ca_certs = ca_certs
        self.set_proxy(host=None, proxy_type=None)

    def set_proxy(self, host, port=None, headers=None,
                  proxy_type='CONNECT'):
        """
        Configure proxy for API calls. Supported proxy_type values:

        'CONNECT' - HTTP proxy with CONNECT.
        None - Disable proxy.
        """
        if proxy_type not in ('CONNECT', None):
            raise NotImplementedError('proxy_type=%s' % (proxy_type,))
        self.proxy_headers = headers
        self.proxy_host = host
        self.proxy_port = port
        self.proxy_type = proxy_type

    def api_call(self, method, path, params):
        """
        Call a Duo API method. Return a (status, reason, data) tuple.
        """
        # urllib cannot handle unicode strings properly. quote() excepts,
        # and urlencode() replaces them with '?'.
        params = encode_params(params)

        now = email.utils.formatdate()
        auth = sign(self.ikey,
                    self.skey,
                    method,
                    self.host,
                    path,
                    now,
                    self.sig_version,
                    params)
        headers = {
            'Authorization': auth,
            'Date': now,
        }

        if method in ['POST', 'PUT']:
            headers['Content-type'] = 'application/x-www-form-urlencoded'
            body = urllib.urlencode(params, doseq=True)
            uri = path
        else:
            body = None
            uri = path + '?' + urllib.urlencode(params, doseq=True)

        # Host and port for the HTTP(S) connection to the API server.
        if self.ca_certs == 'HTTP':
            api_port = 80
            api_proto = 'http'
        else:
            api_port = 443
            api_proto = 'https'

        # Host and port for outer HTTP(S) connection if proxied.
        if self.proxy_type is None:
            host = self.host
            port = api_port
        elif self.proxy_type == 'CONNECT':
            host = self.proxy_host
            port = self.proxy_port
        else:
            raise NotImplementedError('proxy_type=%s' % (self.proxy_type,))

        # Create outer HTTP(S) connection.
        conn = CertValidatingHTTPSConnection(host,
                                             port,
                                             ca_certs=self.ca_certs)

        # Configure CONNECT proxy tunnel, if any.
        if self.proxy_type == 'CONNECT':
            # Ensure the request has the correct Host.
            uri = ''.join((api_proto, '://', self.host, uri))
            if hasattr(conn, 'set_tunnel'): # 2.7+
                conn.set_tunnel(self.host,
                                api_port,
                                self.proxy_headers)
            elif hasattr(conn, '_set_tunnel'): # 2.6.3+
                # pylint: disable=E1103
                conn._set_tunnel(self.host,
                                 api_port,
                                 self.proxy_headers)
                # pylint: enable=E1103

        conn.request(method, uri, body, headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()

        return (response, data)

    def json_api_call(self, method, path, params):
        """
        Call a Duo API method which is expected to return a JSON body
        with a 200 status. Return the response data structure or raise
        RuntimeError.
        """
        (response, data) = self.api_call(method, path, params)
        if response.status != 200:
            msg = 'Received %s %s' % (response.status, response.reason)
            try:
                data = json.loads(data)
                if data['stat'] == 'FAIL':
                    if 'message_detail' in data:
                        msg = 'Received %s %s (%s)' % (
                            response.status,
                            data['message'],
                            data['message_detail'],
                        )
                    else:
                        msg = 'Received %s %s' % (
                            response.status,
                            data['message'],
                        )
            except (ValueError, KeyError, TypeError):
                pass
            error = RuntimeError(msg)
            error.status = response.status
            error.reason = response.reason
            error.data = data
            raise error
        try:
            data = json.loads(data)
            if data['stat'] != 'OK':
                raise RuntimeError('Received error response: %s' % data)
            return data['response']
        except (ValueError, KeyError, TypeError):
            raise RuntimeError('Received bad response: %s' % data)

### The following code was adapted from:
### https://googleappengine.googlecode.com/svn-history/r136/trunk/python/google/appengine/tools/https_wrapper.py

# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import httplib
import re
import socket
import ssl

class InvalidCertificateException(httplib.HTTPException):
  """Raised when a certificate is provided with an invalid hostname."""

  def __init__(self, host, cert, reason):
    """Constructor.

    Args:
      host: The hostname the connection was made to.
      cert: The SSL certificate (as a dictionary) the host returned.
    """
    httplib.HTTPException.__init__(self)
    self.host = host
    self.cert = cert
    self.reason = reason

  def __str__(self):
    return ('Host %s returned an invalid certificate (%s): %s\n'
            'To learn more, see '
            'http://code.google.com/appengine/kb/general.html#rpcssl' %
            (self.host, self.reason, self.cert))

class CertValidatingHTTPSConnection(httplib.HTTPConnection):
  """An HTTPConnection that connects over SSL and validates certificates."""

  default_port = httplib.HTTPS_PORT

  def __init__(self, host, port=None, key_file=None, cert_file=None,
               ca_certs=None, strict=None, **kwargs):
    """Constructor.

    Args:
      host: The hostname. Can be in 'host:port' form.
      port: The port. Defaults to 443.
      key_file: A file containing the client's private key
      cert_file: A file containing the client's certificates
      ca_certs: A file contianing a set of concatenated certificate authority
          certs for validating the server against.
      strict: When true, causes BadStatusLine to be raised if the status line
          can't be parsed as a valid HTTP/1.0 or 1.1 status line.
    """
    httplib.HTTPConnection.__init__(self, host, port, strict, **kwargs)
    self.key_file = key_file
    self.cert_file = cert_file
    self.ca_certs = ca_certs
    if self.ca_certs:
      self.cert_reqs = ssl.CERT_REQUIRED
    else:
      self.cert_reqs = ssl.CERT_NONE

  def _GetValidHostsForCert(self, cert):
    """Returns a list of valid host globs for an SSL certificate.

    Args:
      cert: A dictionary representing an SSL certificate.
    Returns:
      list: A list of valid host globs.
    """
    if 'subjectAltName' in cert:
      return [x[1] for x in cert['subjectAltName'] if x[0].lower() == 'dns']
    else:
      return [x[0][1] for x in cert['subject']
              if x[0][0].lower() == 'commonname']

  def _ValidateCertificateHostname(self, cert, hostname):
    """Validates that a given hostname is valid for an SSL certificate.

    Args:
      cert: A dictionary representing an SSL certificate.
      hostname: The hostname to test.
    Returns:
      bool: Whether or not the hostname is valid for this certificate.
    """
    hosts = self._GetValidHostsForCert(cert)
    for host in hosts:
      host_re = host.replace('.', '\.').replace('*', '[^.]*')
      if re.search('^%s$' % (host_re,), hostname, re.I):
        return True
    return False

  def connect(self):
    "Connect to a host on a given (SSL) port."
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((self.host, self.port))
    self.sock = sock
    if self._tunnel_host:
      self._tunnel()
    self.sock = ssl.wrap_socket(self.sock, keyfile=self.key_file,
                                certfile=self.cert_file,
                                cert_reqs=self.cert_reqs,
                                ca_certs=self.ca_certs)
    if self.cert_reqs & ssl.CERT_REQUIRED:
      cert = self.sock.getpeercert()
      hostname = self.host.split(':', 0)[0]
      if not self._ValidateCertificateHostname(cert, hostname):
        raise InvalidCertificateException(hostname, cert, 'hostname mismatch')

### duo_openvpn_as.py integration code:

def log(msg):
    msg = 'Duo OpenVPN_AS: %s' % msg
    syslog.syslog(msg)

class OpenVPNIntegration(Client):
    def api_call(self, *args, **kwargs):
        orig_ca_certs = self.ca_certs
        try:
            with tempfile.NamedTemporaryFile() as fp:
                fp.write(CA_CERT)
                fp.flush()
                self.ca_certs = fp.name
                return Client.api_call(self, *args, **kwargs)
        finally:
            self.ca_certs = orig_ca_certs

    def preauth(self, username):
        log('pre-authentication for %s' % username)

        params = {
            'user': username,
        }

        response = self.json_api_call('POST', '/rest/v1/preauth', params)

        result = response.get('result')

        if not result:
            log('invalid API response: %s' % response)
            raise RuntimeError('invalid API response: %s' % response)
            return

        if result == API_RESULT_AUTH:
            log('secondary authentication required for user %s' % username)
            msg = 'Duo passcode or second factor:'
            return (result, msg)

        status = response.get('status')

        if not status:
            log('invalid API response: %s' % response)
            raise RuntimeError('invalid API response: %s' % response)
        msg = status

        if result == API_RESULT_ENROLL:
            log('user %s is not enrolled: %s' % (username, status))
        elif result == API_RESULT_DENY:
            log('preauth failure for %s: %s' % (username, status))
        elif result == API_RESULT_ALLOW:
            log('preauth success for %s: %s' % (username, status))
        else:
            log('unknown preauth result: %s' % result)

        return (result, msg)

    def auth(self, username, password, ipaddr):
        log('authentication for %s' % username)

        params = {
            'user': username,
            'factor': 'auto',
            'auto': password,
            'ipaddr': ipaddr
        }

        response = self.json_api_call('POST', '/rest/v1/auth', params)

        result = response.get('result')
        status = response.get('status')

        if not result or not status:
            log('invalid API response: %s' % response)
            raise RuntimeError('invalid API response: %s' % response)
            return

        if result == API_RESULT_ALLOW:
            log('auth success for %s: %s' % (username, status))
        elif result == API_RESULT_DENY:
            log('auth failure for %s: %s' % (username, status))
        else:
            log('unknown auth result: %s' % result)

        return result, status

api = OpenVPNIntegration(IKEY, SKEY, HOST)
if PROXY_HOST:
    api.set_proxy(host=PROXY_HOST, port=PROXY_PORT)

def post_auth_cr(authcred, attributes, authret, info, crstate):
    # Don't do challenge/response on sessions or autologin clients.
    # autologin client: a client that has been issued a special
    #   certificate allowing authentication with only a certificate
    #   (used for unattended clients such as servers).
    # session: a client that has already authenticated and received
    #   a session token.  The client is attempting to authenticate
    #   again using the session token.

    if info.get('auth_method') in ('session', 'autologin'):
        return authret

    username = authcred['username']
    ipaddr = authcred['client_ip_addr']

    if crstate.get('challenge'):
        # response to dynamic challenge
        duo_pass = crstate.response()

        # received response
        crstate.expire()
        try:
            result, msg = api.auth(username, duo_pass, ipaddr)
            if result == API_RESULT_ALLOW:
                authret['status'] = SUCCEED
                authret['reason'] = msg
            else:
                authret['status'] = FAIL
                authret['reason'] = msg
            authret['client_reason'] = authret['reason']
        except Exception as e:
            log(traceback.format_exc())
            authret['status'] = FAIL
            authret['reason'] = "Exception caught in auth: %s" % e
            authret['client_reason'] = \
                "Unknown error communicating with Duo service"
    else:
        # initial auth request; issue challenge
        try:
            result, msg = api.preauth(username)
            if result == API_RESULT_AUTH:
                # save state indicating challenge has been issued
                crstate['challenge'] = True
                crstate.challenge_post_auth(authret, msg, echo=True)
            elif result == API_RESULT_ENROLL:
                authret['status'] = FAIL

                # Attempt to detect whether the login came from a web client
                # or a native client
                if attributes.get('log_service_name') == 'WEB_CLIENT':
                    # It's pretty reasonable to copy/paste the enrollment
                    # link when it's displayed in a web client
                    authret['reason'] = msg
                else:
                    # Native clients tend not to be in a good position to
                    # show an enrollment link (e.g. on windows, it shows
                    # up in a temporary balloon popup from the
                    # systray), so we'll replace it with a generic message.
                    authret['reason'] = ('User account has not been '
                                         'enrolled for Duo authentication')
                authret['client_reason'] = authret['reason']
            elif result != API_RESULT_ALLOW:
                authret['status'] = FAIL
                authret['reason'] = msg
                authret['client_reason'] = authret['reason']
        except Exception as e:
            log(traceback.format_exc())
            authret['status'] = FAIL
            authret['reason'] = "Exception caught in pre-auth: %s" % e
            authret['client_reason'] = \
                "Unknown error communicating with Duo service"

    return authret
