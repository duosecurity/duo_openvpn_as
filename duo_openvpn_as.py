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

# Set SKIP_DUO_ON_VPN_AUTH to True to skip Duo authentication for VPN
# connections. Two-factor will only be required for other
# authentications (like web server access).
SKIP_DUO_ON_VPN_AUTH = False

# Set AUTOPUSH to True to automatically prompt the user's default 2FA device.
# This will remove any user prompts for factor selection.
AUTOPUSH = False

# The text of the prompt that will ask the user for their choice of factor or 
# their passcode.
PASSCODE_OR_FACTOR_PROMPT = 'Duo passcode or second factor:'

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

CA_CERT = """
subject= /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Assured ID Root CA
-----BEGIN CERTIFICATE-----
MIIDtzCCAp+gAwIBAgIQDOfg5RfYRv6P5WD8G/AwOTANBgkqhkiG9w0BAQUFADBl
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
b3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzExMTEwMDAwMDAwWjBlMQswCQYDVQQG
EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
cnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtDhXO5EOAXLGH87dg+XESpa7c
JpSIqvTO9SA5KFhgDPiA2qkVlTJhPLWxKISKityfCgyDF3qPkKyK53lTXDGEKvYP
mDI2dsze3Tyoou9q+yHyUmHfnyDXH+Kx2f4YZNISW1/5WBg1vEfNoTb5a3/UsDg+
wRvDjDPZ2C8Y/igPs6eD1sNuRMBhNZYW/lmci3Zt1/GiSw0r/wty2p5g0I6QNcZ4
VYcgoc/lbQrISXwxmDNsIumH0DJaoroTghHtORedmTpyoeb6pNnVFzF1roV9Iq4/
AUaG9ih5yLHa5FcXxH4cDrC0kqZWs72yl+2qp/C3xag/lRbQ/6GW6whfGHdPAgMB
AAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBRF66Kv9JLLgjEtUYunpyGd823IDzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYun
pyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEAog683+Lt8ONyc3pklL/3cmbYMuRC
dWKuh+vy1dneVrOfzM4UKLkNl2BcEkxY5NM9g0lFWJc1aRqoR+pWxnmrEthngYTf
fwk8lOa4JiwgvT2zKIn3X/8i4peEH+ll74fg38FnSbNd67IJKusm7Xi+fT8r87cm
NW1fiQG2SVufAQWbqz0lwcy2f8Lxb4bG+mRo64EtlOtCt/qMHt1i8b5QZ7dsvfPx
H2sMNgcWfzd8qVttevESRmCD1ycEvkvOl77DZypoEd+A5wwzZr8TDRRu838fYxAe
+o0bJW1sj6W3YQGx0qMmoRBxna3iw/nDmVG3KwcIzi7mULKn+gpFL6Lw8g==
-----END CERTIFICATE-----

subject= /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Global Root CA
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
-----END CERTIFICATE-----

subject= /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2Ug
RVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm
+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTW
PNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEM
xChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFB
Ik5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3
hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsg
EsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaA
FLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3Nec
nzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6z
eM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jF
hS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2
Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCe
vEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep
+OkuE6N36B9K
-----END CERTIFICATE-----

subject= /C=US/O=SecureTrust Corporation/CN=SecureTrust CA
-----BEGIN CERTIFICATE-----
MIIDuDCCAqCgAwIBAgIQDPCOXAgWpa1Cf/DrJxhZ0DANBgkqhkiG9w0BAQUFADBI
MQswCQYDVQQGEwJVUzEgMB4GA1UEChMXU2VjdXJlVHJ1c3QgQ29ycG9yYXRpb24x
FzAVBgNVBAMTDlNlY3VyZVRydXN0IENBMB4XDTA2MTEwNzE5MzExOFoXDTI5MTIz
MTE5NDA1NVowSDELMAkGA1UEBhMCVVMxIDAeBgNVBAoTF1NlY3VyZVRydXN0IENv
cnBvcmF0aW9uMRcwFQYDVQQDEw5TZWN1cmVUcnVzdCBDQTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKukgeWVzfX2FI7CT8rU4niVWJxB4Q2ZQCQXOZEz
Zum+4YOvYlyJ0fwkW2Gz4BERQRwdbvC4u/jep4G6pkjGnx29vo6pQT64lO0pGtSO
0gMdA+9tDWccV9cGrcrI9f4Or2YlSASWC12juhbDCE/RRvgUXPLIXgGZbf2IzIao
wW8xQmxSPmjL8xk037uHGFaAJsTQ3MBv396gwpEWoGQRS0S8Hvbn+mPeZqx2pHGj
7DaUaHp3pLHnDi+BeuK1cobvomuL8A/b01k/unK8RCSc43Oz969XL0Imnal0ugBS
8kvNU3xHCzaFDmapCJcWNFfBZveA4+1wVMeT4C4oFVmHursCAwEAAaOBnTCBmjAT
BgkrBgEEAYI3FAIEBh4EAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB
/zAdBgNVHQ4EFgQUQjK2FvoE/f5dS3rD/fdMQB1aQ68wNAYDVR0fBC0wKzApoCeg
JYYjaHR0cDovL2NybC5zZWN1cmV0cnVzdC5jb20vU1RDQS5jcmwwEAYJKwYBBAGC
NxUBBAMCAQAwDQYJKoZIhvcNAQEFBQADggEBADDtT0rhWDpSclu1pqNlGKa7UTt3
6Z3q059c4EVlew3KW+JwULKUBRSuSceNQQcSc5R+DCMh/bwQf2AQWnL1mA6s7Ll/
3XpvXdMc9P+IBWlCqQVxyLesJugutIxq/3HcuLHfmbx8IVQr5Fiiu1cprp6poxkm
D5kuCLDv/WnPmRoJjeOnnyvJNjR7JLN4TJUXpAYmHrZkUjZfYGfZnMUFdAvnZyPS
CPyI6a6Lf+Ew9Dd+/cYy2i2eRDAwbO4H3tI0/NL/QPZL9GZGBlSm8jIKYyYwa5vR
3ItHuuG51WLQoqD0ZwV4KWMabwTW+MZMo5qxN7SN5ShLHZ4swrhovO0C7jE=
-----END CERTIFICATE-----

subject= /C=US/O=SecureTrust Corporation/CN=Secure Global CA
-----BEGIN CERTIFICATE-----
MIIDvDCCAqSgAwIBAgIQB1YipOjUiolN9BPI8PjqpTANBgkqhkiG9w0BAQUFADBK
MQswCQYDVQQGEwJVUzEgMB4GA1UEChMXU2VjdXJlVHJ1c3QgQ29ycG9yYXRpb24x
GTAXBgNVBAMTEFNlY3VyZSBHbG9iYWwgQ0EwHhcNMDYxMTA3MTk0MjI4WhcNMjkx
MjMxMTk1MjA2WjBKMQswCQYDVQQGEwJVUzEgMB4GA1UEChMXU2VjdXJlVHJ1c3Qg
Q29ycG9yYXRpb24xGTAXBgNVBAMTEFNlY3VyZSBHbG9iYWwgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvNS7YrGxVaQZx5RNoJLNP2MwhR/jxYDiJ
iQPpvepeRlMJ3Fz1Wuj3RSoC6zFh1ykzTM7HfAo3fg+6MpjhHZevj8fcyTiW89sa
/FHtaMbQbqR8JNGuQsiWUGMu4P51/pinX0kuleM5M2SOHqRfkNJnPLLZ/kG5VacJ
jnIFHovdRIWCQtBJwB1g8NEXLJXr9qXBkqPFwqcIYA1gBBCWeZ4WNOaptvolRTnI
HmX5k/Wq8VLcmZg9pYYaDDUz+kulBAYVHDGA76oYa8J719rO+TMg1fW9ajMtgQT7
sFzUnKPiXB3jqUJ1XnvUd+85VLrJChgbEplJL4hL/VBi0XPnj3pDAgMBAAGjgZ0w
gZowEwYJKwYBBAGCNxQCBAYeBABDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQF
MAMBAf8wHQYDVR0OBBYEFK9EBMJBfkiD2045AuzshHrmzsmkMDQGA1UdHwQtMCsw
KaAnoCWGI2h0dHA6Ly9jcmwuc2VjdXJldHJ1c3QuY29tL1NHQ0EuY3JsMBAGCSsG
AQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBBQUAA4IBAQBjGghAfaReUw132HquHw0L
URYD7xh8yOOvaliTFGCRsoTciE6+OYo68+aCiV0BN7OrJKQVDpI1WkpEXk5X+nXO
H0jOZvQ8QCaSmGwb7iRGDBezUqXbpZGRzzfTb+cnCDpOGR86p1hcF895P4vkp9Mm
I50mD1hp/Ed+stCNi5O/KU9DaXR2Z0vPB4zmAve14bRDtUstFJ/53CYNv6ZHdAbY
iNE6KTCEztI5gGIbqMdXSbxqVVFnFUq+NQfk1XWYN3kwFNspnWzFacxHVaIw98xc
f8LDmBxrThaA63p4ZUWiABqvDA1VZDRIuJK58bRQKfJPIx/abKwfROHdI3hRW8cW
-----END CERTIFICATE-----
"""

### OpenVPN Access Server imports post-auth scripts into database
### blobs, so we have to include dependencies inline.

### The following code was adapted from duo_client_python.

import base64
import email.utils
import hashlib
import hmac
import json

try:
    # Unicode only exists in python 2
    text_type = unicode
except NameError:
    # Python 3 text_type is the string object
    text_type = str

def canon_params(params):
    args = []
    for key in sorted(params.keys()):
        val = params[key]
        arg = '%s=%s' % (quote(key, '~'), quote(val, '~'))
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
    if isinstance(skey, text_type):
        skey = skey.encode('utf-8')

    if isinstance(canonical, text_type):
        canonical = canonical.encode('utf-8')

    sig = hmac.new(skey, canonical, hashlib.sha512)
    auth = '%s:%s' % (ikey, sig.hexdigest())

    if isinstance(auth, text_type):
        auth = auth.encode('utf-8')

    auth = base64.b64encode(auth)

    if not isinstance(auth, text_type):
        auth = auth.decode('utf-8')

    return 'Basic %s' % auth


def encode_params(params):
    """Returns copy of params with unicode strings utf-8 encoded"""
    new_params = {}
    for key, value in params.items():
        if isinstance(key, text_type):
            key = key.encode("utf-8")
        if isinstance(value, text_type):
            value = value.encode("utf-8")
        new_params[key] = value
    return new_params


class Client(object):
    sig_version = 1

    def __init__(self, ikey, skey, host,
                 ca_certs=None,
                 user_agent=None):
        """
        ca - Path to CA pem file.
        """
        self.ikey = ikey
        self.skey = skey
        self.host = host
        self.ca_certs = ca_certs
        self.set_proxy(host=None, proxy_type=None)
        self.user_agent = user_agent

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
            'Host': self.host,
        }

        if self.user_agent:
            headers['User-Agent'] = self.user_agent

        if method in ['POST', 'PUT']:
            headers['Content-type'] = 'application/x-www-form-urlencoded'
            body = urlencode(params, doseq=True)
            uri = path
        else:
            body = None
            uri = path + '?' + urlencode(params, doseq=True)

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

try:
    import httplib
except ImportError:
    import http.client as httplib

try:
    from urllib import quote, urlencode
except ImportError:
    from urllib.parse import quote, urlencode

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

    context = ssl.create_default_context()
    context.load_verify_locations(cafile=self.ca_certs)

    if self.cert_file:
        context.load_cert_chain(self.cert_file, keyfile=self.key_file)

    ssl_version_blacklist = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    context.options = self.cert_reqs | ssl_version_blacklist

    self.sock = context.wrap_socket(self.sock, server_hostname=self.host)

    if self.cert_reqs & ssl.CERT_REQUIRED:
      cert = self.sock.getpeercert()
      cert_validation_host = self._tunnel_host or self.host
      hostname = cert_validation_host.split(':', 0)[0]
      if not self._ValidateCertificateHostname(cert, hostname):
        raise InvalidCertificateException(hostname, cert, 'hostname mismatch')

### duo_openvpn_as.py integration code:

__version__ = '2.6'

def log(msg):
    msg = 'Duo OpenVPN_AS: %s' % msg
    syslog.syslog(msg)


class PreauthResponse(dict):
    @property
    def factors(self):
        return self.get('factors', {})

    @property
    def msg(self):
        """Alias for status"""

        return self.status

    @msg.setter
    def msg(self, value):
        """Alias for status"""
        self['status'] = value

    @property
    def result(self):
        return self.get('result')

    @property
    def status(self):
        return self.get('status')

    @status.setter
    def status(self, value):
        self['status'] = value


class OpenVPNIntegration(Client):
    def __init__(self, *args, **kwargs):
        kwargs['user_agent'] = 'duo_openvpn_as/' + __version__
        super(OpenVPNIntegration, self).__init__(*args, **kwargs)

    def api_call(self, *args, **kwargs):
        orig_ca_certs = self.ca_certs
        try:
            with tempfile.NamedTemporaryFile() as fp:
                fp.write(CA_CERT.encode('utf-8'))
                fp.flush()
                self.ca_certs = fp.name
                return Client.api_call(self, *args, **kwargs)
        finally:
            self.ca_certs = orig_ca_certs

    def preauth(self, username, ipaddr):
        log('pre-authentication for %s' % username)

        params = {
            'user': username,
        }

        if ipaddr:
            params['ipaddr'] = ipaddr

        response = PreauthResponse(self.json_api_call('POST', '/rest/v1/preauth', params))

        result = response.result

        if not result:
            log('invalid API response: %s' % response)
            raise RuntimeError('invalid API response: %s' % response)

        if result == API_RESULT_AUTH:
            log('secondary authentication required for user %s' % username)
            response.msg = PASSCODE_OR_FACTOR_PROMPT
            return response

        status = response.status

        if not status:
            log('invalid API response: %s' % response)
            raise RuntimeError('invalid API response: %s' % response)

        if result == API_RESULT_ENROLL:
            log('user %s is not enrolled: %s' % (username, status))
        elif result == API_RESULT_DENY:
            log('preauth failure for %s: %s' % (username, status))
        elif result == API_RESULT_ALLOW:
            log('preauth success for %s: %s' % (username, status))
        else:
            log('unknown preauth result: %s' % result)

        return response

    def auth(self, username, password, ipaddr):
        log('authentication for %s' % username)

        params = {
            'user': username,
            'factor': 'auto',
            'auto': password,
        }

        if ipaddr:
            params['ipaddr'] = ipaddr


        response = self.json_api_call('POST', '/rest/v1/auth', params)

        result = response.get('result')
        status = response.get('status')

        if not result or not status:
            log('invalid API response: %s' % response)
            raise RuntimeError('invalid API response: %s' % response)

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


def auth_and_update_result_structure(username, factor, ipaddr, authret):
    """ Send the Duo 2FA and then populate the OpenVPN
    return structure with the result.
    """
    try:
        result, msg = api.auth(username, factor, ipaddr)
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

    return authret


def post_auth_cr(authcred, attributes, authret, info, crstate):
    # Don't do challenge/response on sessions or autologin clients.
    # autologin client: a client that has been issued a special
    #   certificate allowing authentication with only a certificate
    #   (used for unattended clients such as servers).
    # session: a client that has already authenticated and received
    #   a session token.  The client is attempting to authenticate
    #   again using the session token.

    auth_method = info.get('auth_method')
    if auth_method in ('session', 'autologin'):
        log("skipping auth method=%s" % auth_method)

        return authret

    if SKIP_DUO_ON_VPN_AUTH and attributes.get('vpn_auth'):
        return authret

    username = authcred['username']
    ipaddr = authcred.get('client_ip_addr')

    if crstate.get("challenge"):
        # response to dynamic challenge
        duo_pass = crstate.response()

        # received response
        crstate.expire()
        authret = auth_and_update_result_structure(username, duo_pass, ipaddr, authret)
    else:
        log("initial auth request")

        # initial auth request; issue challenge
        try:
            response = api.preauth(username, ipaddr)
            result, msg = response.result, response.msg
            if result == API_RESULT_AUTH:
                # when the preauth result comes back as requiring authentication
                # try to automatically respond to this with the "push" key
                if AUTOPUSH:
                    autopush_factor = response.factors.get('default')

                    log("Autopushing user: %s, autopush_factor=%s" % (username, autopush_factor))

                    authret = auth_and_update_result_structure(username, autopush_factor, ipaddr, authret)
                else:
                    log("prompt for challenge")
                    # save state indicating challenge has been issued
                    crstate["challenge"] = True
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
