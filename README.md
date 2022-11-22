# Overview

[![Issues](https://img.shields.io/github/issues/duosecurity/duo_openvpn_as)](https://github.com/duosecurity/duo_openvpn_as/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_openvpn_as)](https://github.com/duosecurity/duo_openvpn_as/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_openvpn_as)](https://github.com/duosecurity/duo_openvpn_as/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_confluence/blob/master/LICENSE)

**duo_openvpn_as** - Duo two-factor authentication for OpenVPN Access Server

# Installing

Download the [latest Duo OpenVPN Access Server release](https://github.com/duosecurity/duo_openvpn_as/archive/refs/heads/master.zip) as a zip file from GitHub and unzip the package on your own OpenVPN Access Server.

# Usage

## Configuring & Enabling the Post-Auth Script
Make sure you have your OpenVPN Access Server's integration key (IKEY), secret key (SKEY), and API hostname. You can find these in your Duo Admin Panel under the Applications tab.

Open the duo_openvpn_as.py script in a text editor and fill in your IKEY, SKEY, and API hostname in the following area:
```
# ------------------------------------------------------------------
# Fill in your integration credentials on the following three lines:
IKEY = 'INTEGRATION_KEY'
SKEY = 'SECRET_KEY'
HOST = 'API_HOSTNAME'
# ------------------------------------------------------------------
```

Then, move the duo_openvon_as.py script to the OpenVPN AS scripts folder. This typically can be found in /usr/local/openvpn_as/scripts/. Make sure it is executable.

```
$ mv duo_openvpn_as.py /usr/local/openvpn_as/scripts/
$ chmod a+x /usr/local/openvpn_as/scripts/duo_openvpn_as.py
 ```
Then, set duo_openvpn_as.py as your post-auth script:\
```
$ /usr/local/openvpn_as/scripts/sacli -a admin_username -i -k auth.module.post_auth_script --value_file=/usr/local/openvpn_as/scripts/duo_openvpn_as.py ConfigPut
```
where admin_username is the username of an administrator on your OpenVPN Access Server. You'll be prompted to enter the administrator's password.

Finally, restart the service to commit your changes:
```
$ /usr/local/openvpn_as/scripts/sacli -a admin_username -i Reset
```

# Testing
Try to log in as a regular VPN user through the OpenVPN Access Server web interface. If you're using an account that has not been enrolled for Duo authentication, your login attempt will be denied with a self-enrollment URL. Visit the URL, enroll, then try again.

Note: You will only receive a self-enrollment URL if you log in to your OpenVPN Access Server instance with a web browser!

When you log in as a Duo-enrolled user, you'll see a secondary prompt with instructions to enter a Duo passcode or alternate factor.

You can choose from doing a push, phone, or sms factor. Additionally, you can specify a number after the factor name to identify which enrolled device you are using.

# Support

The full documentation for OpenVPN Access Server can be found at https://duo.com/docs/openvpn-as.

Report any bugs, feature requests, etc. to us directly at support@duosecurity.com

Have fun!

<http://www.duosecurity.com>
