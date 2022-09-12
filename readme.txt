opvnkeys.py - a script to manage OpenVPN server and client profiles.
------------------------------------------------------------------------------------------

Prerequisites:
--------------
 - OpenVPN (add to path)
   https://openvpn.net/community-downloads/
 - Python3
   https://www.python.org/
 - Python requests
   python3 -m pip install requests

How to use:
-----------
(1) Rename ovpnkeys.ini.example to ovpnkeys.ini and adjust the configuration for your
    needs.

client.ovpn.template and server.ovpn.template can also be configured according to your
network needs. These files are used directly and don't need to be renamed.

openssl.cnf can also be modified, but typically this is what most people should use.

(2) Run `ovpnkeys.py init`

This will initialize your certificate database and generate your root certificate.

(3) For servers, run `ovpnkeys.py server --name <name>`

This will generate a server profile and store it in db/profiles/<name>.ovpn. Load this
into OpenVPN with `openvpn --config <profile>` and it will start a server. You can also
start it as a service (if that is installed). When starting as a service, the service will
look for the first configuration file in the config folder.

For extra security, you can delete the private key and .ovpn file after the profile is
loaded on the target machine.

(4) For clients, run `ovpnkeys.py client --name <name>`

Use a unique name per client. Share the generated .ovpn profile with the client.

For extra security, you can delete the private key and .ovpn file after the profile is
loaded on the target machine. The private key is loaded inline in the .ovpn file so you
do not need to share it separately.

(5) For revocations, `ovpnkeys.py revoke --name <name>`

It will revoke the current certificate generated for that name.

(6) For CRL updates, `ovpnkeys.py crl`

If you have set up the CRL endpoint, this will refresh the CRL file on the remote host.

In the configuration, "crl_url" is the URL that points to the current CRL file.
"crl_updater" points to a script to handle updating the CRL file stored on the server.

update_vpn_crl.php is provided as an example uploader. It accepts a POST request
containing the new CRL, and it verifies it against your root certificate to determine if
the request is authentic.

If using a CRL endpoint, `ovpnkeys.py crl` should be regularly issued to keep it from
expiring.