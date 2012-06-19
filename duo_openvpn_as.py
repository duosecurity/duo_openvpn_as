#!/usr/bin/env python
#
# duo_openvpn_as.py
# Duo OpenVPN v1
# Copyright 2012 Duo Security, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# ------------------------------------------------------------------
# Fill in your integration credentials on the following three lines:
IKEY = '<DUO INTEGRATION KEY HERE>'
SKEY = '<DUO INTEGRATION SECRET KEY HERE>'
HOST = '<DUO API HOSTNAME HERE>'
# ------------------------------------------------------------------

import base64
import functools
import hashlib
import hmac
import itertools
import json
import syslog
import tempfile
import traceback
import urllib

from pyovpn.plugin import *

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

_ca_cert_file = None
def write_ca_certs(func):
    """ Decorator to write the contents of CA_CERT to a (securely-created)
    named tempfile, save that name in our global _ca_cert_file, call
    the wrapped function, then close the temp file and reset
    _ca_cert_file to None when done.

    We do this because python's SSL module requires that certificates
    be in *real* files on disk...
    """

    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        global _ca_cert_file
        try:
            with tempfile.NamedTemporaryFile() as fp:
                fp.write(CA_CERT)
                fp.flush()
                _ca_cert_file = fp.name
                return func(*args, **kwargs)
        finally:
            _ca_cert_file = None
    return wrapped

def canonicalize(method, host, uri, params):
    canon = [method.upper(), host.lower(), uri]

    args = []
    for key in sorted(params.keys()):
        val = params[key]
        arg = '%s=%s' % (urllib.quote(key, '~'), urllib.quote(val, '~'))
        args.append(arg)
    canon.append('&'.join(args))

    return '\n'.join(canon)

def sign(ikey, skey, method, host, uri, params):
    sig = hmac.new(skey, canonicalize(method, host, uri, params), hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())
    return 'Basic %s' % base64.b64encode(auth)

def call(ikey, skey, host, method, path, **kwargs):
    headers = {'Authorization':sign(ikey, skey, method, host, path, kwargs)}

    if method in [ 'POST', 'PUT' ]:
        headers['Content-type'] = 'application/x-www-form-urlencoded'
        body = urllib.urlencode(kwargs, doseq=True)
        uri = path
    else:
        body = None
        uri = path + '?' + urllib.urlencode(kwargs, doseq=True)

    conn = CertValidatingHTTPSConnection(host, 443, ca_certs=_ca_cert_file)
    conn.request(method, uri, body, headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()

    return (response.status, response.reason, data)

def api(ikey, skey, host, method, path, **kwargs):
    (status, reason, data) = call(ikey, skey, host, method, path, **kwargs)
    if status != 200:
        raise RuntimeError('Received %s %s: %s' % (status, reason, data))

    try:
        data = json.loads(data)
        if data['stat'] != 'OK':
            raise RuntimeError('Received error response: %s' % data)
        return data['response']
    except (ValueError, KeyError):
        raise RuntimeError('Received bad response: %s' % data)

def log(msg):
    msg = 'Duo OpenVPN_AS: %s' % msg
    syslog.syslog(msg)

def preauth(ikey, skey, host, username):
    log('pre-authentication for %s' % username)

    args = {
        'user': username,
    }

    response = api(ikey, skey, host, 'POST', '/rest/v1/preauth', **args)

    result = response.get('result')

    if not result:
        log('invalid API response: %s' % response)
        raise RuntimeError('invalid API response: %s' % response)
        return

    if result == API_RESULT_AUTH:
        log('secondary authentication required for user %s' % username)

        factors = response.get('factors')
        if factors is None:
            log('invalid API response: %s' % response)
            raise RuntimeError('invalid API response: %s' % response)

        factors_list = []
        for i in itertools.count(1):
            factor = factors.get(str(i))
            if factor is None:
                break
            factors_list.append(factor)
        msg = ('Enter Duo passcode or out-of-band factor (%s):'
               % ', '.join(factors_list))

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

def auth(ikey, skey, host, username, password, ipaddr):
    log('authentication for %s' % username)

    args = {
        'user': username,
        'factor': 'auto',
        'auto': password,
        'ipaddr': ipaddr
    }

    response = api(ikey, skey, host, 'POST', '/rest/v1/auth', **args)

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

@write_ca_certs
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

    duo_pass = crstate.response()          # response to dynamic challenge

    if duo_pass:
        # received response
        crstate.expire()
        try:
            result, msg = auth(IKEY, SKEY, HOST, username, duo_pass, ipaddr)
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

    elif crstate.get('challenge'):
        # received an empty or null response after challenge issued

        # make sure to expire crstate at the end of the
        # challenge/response transaction
        crstate.expire()
        authret['status'] = FAIL
        authret['reason'] = "No response was provided to Duo challenge"

        # allow end user to see actual error text
        authret['client_reason'] = authret['reason']

    else:
        # initial auth request without static response; issue challenge
        try:
            result, msg = preauth(IKEY, SKEY, HOST, username)
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

# OpenVPN Access Server imports post-auth scripts into database blobs,
# so we have to include dependencies inline.

# The following code was adapted from:
# https://googleappengine.googlecode.com/svn-history/r136/trunk/python/google/appengine/tools/https_wrapper.py
#

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
    self.sock = ssl.wrap_socket(sock, keyfile=self.key_file,
                                certfile=self.cert_file,
                                cert_reqs=self.cert_reqs,
                                ca_certs=self.ca_certs)
    if self.cert_reqs & ssl.CERT_REQUIRED:
      cert = self.sock.getpeercert()
      hostname = self.host.split(':', 0)[0]
      if not self._ValidateCertificateHostname(cert, hostname):
        raise InvalidCertificateException(hostname, cert, 'hostname mismatch')
