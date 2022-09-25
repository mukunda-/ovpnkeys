#!/usr/bin/python3
##########################################################################################
# ovpnkeys.py
#
# Copyright 2022 Mukunda Johnson
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
# OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
##########################################################################################

# Phil's work is an excellent reference
# https://www.phildev.net/ssl/

import os, subprocess, argparse, configparser, sys, re, requests

#-----------------------------------------------------------------------------------------
Args   = None
Config = None

class NoDefault: pass

#-----------------------------------------------------------------------------------------
def conf(key, default=NoDefault):
   if default is NoDefault:
      return Config["ovpnkeys"][key]
   else:
      return Config["ovpnkeys"].get(key, default)

#-----------------------------------------------------------------------------------------
def confb(key, default=NoDefault):
   return Config.getboolean("ovpnkeys", key, fallback=default)

#-----------------------------------------------------------------------------------------
def printErr(*args, **kwargs):
   print("Error:", *args, **kwargs, file=sys.stderr)

#-----------------------------------------------------------------------------------------
def loadConfig():
   global Config
   if not os.path.exists("ovpnkeys.ini"):
      printErr("ovpnkeys.ini not found. Copy the template ovpnkeys.ini.example")
      sys.exit(-1)

   Config = configparser.ConfigParser()
   Config.read("ovpnkeys.ini")
   os.environ["OVPNKEYS_CA"] = conf("dir")
   os.environ["OVPNKEYS_CRL"] = conf("crl_url", "")

#-----------------------------------------------------------------------------------------
def cdir(*parts):
   return os.path.join(conf("dir"), *parts)

#-----------------------------------------------------------------------------------------
def parseArgs():
   global Args
   
   parser = argparse.ArgumentParser(description="Manage OVPN profiles.")
   parser.add_argument("type", choices=["server", "client", "init", "crl"])
   parser.add_argument("--name", help="Subject name (CN)")
   parser.add_argument("--country", help="Subject country.")
   parser.add_argument("--state", help="Subject state.")
   parser.add_argument("--org", help="Subject organization.")
   parser.add_argument("--ou", help="Subject organization unit.")
   parser.add_argument("--email", help="Subject email.")
   parser.add_argument("--nopass", action="store_true",
      help="Do not password protect generated private key.")
   Args = parser.parse_args()

#-----------------------------------------------------------------------------------------
def getSubjArg(name, country, state, organization, organizationalUnit, email):
   parts = []
   if country != "":
      parts += ["/C=" + country]
   if state != "":
      parts += ["/ST=" + state]
   if organization != "":
      parts += ["/O=" + organization]
   if organizationalUnit != "":
      parts += ["/OU=" + organizationalUnit]
   if email != "":
      parts += ["/emailAddress=" + email]
   key = "/CN=" + name + "".join(parts)
   print("Built subject key:", key)
   return key

#-----------------------------------------------------------------------------------------
def createEmptyFile(filename):
   print("Creating empty file", filename)
   with open(filename, "a"): pass

#-----------------------------------------------------------------------------------------
def initCRL():
   print("Initializing CRL index.")
   with open(cdir("crlnumber"), "w") as f:
      f.write("1000")

#-----------------------------------------------------------------------------------------
def run(args):
   print("Running command:", args)
   subprocess.run(args, check=True, env=os.environ)

#-----------------------------------------------------------------------------------------
def uploadCRL():
   endpoint = conf('crl_updater', '')
   if not endpoint:
      print("No crl_updater specified. Not updating CRL.")
      return

   print("Posting CRL to crl_updater.")
   # Posting CRL to crl_updater.
   resp = requests.post(endpoint, json={
      "crl": readFile(cdir("crl", "crl.pem"))
   })
   print("Got response", resp)
   if resp.status_code != 200:
      print("response text:", resp.text)

#-----------------------------------------------------------------------------------------
def updateCRL():
   run([
      "openssl", "ca", "-gencrl",
      "-config", "openssl.cnf",
      "-out", cdir("crl", "crl.pem")
   ])
   uploadCRL()

#-----------------------------------------------------------------------------------------
def createCAcert():
   print("Creating CA request and key.")
   args = ["openssl", "req", "-new", "-newkey", "rsa",
           "-keyout", cdir("private", "root.pem"),
           "-out", cdir("reqs", "root.csr"),
           "-config", "./openssl.cnf",
           "-subj", getSubjArg(conf("root_name"), conf("country"), conf("state"),
                               conf("organization"), conf("organizational_unit"), "")]
   if confb('no_ca_pass') or Args.nopass:
      args += ["-nodes"]

   run(args)

   print("Self-signing CA.")
   args = ["openssl", "ca", "-batch", "-create_serial",
           "-out", cdir("pub", "root.crt"),
           "-days", conf("root_certification_days"),
           "-keyfile", cdir("private", "root.pem"),
           "-selfsign", "-extensions", "my_v3_ca_exts",
           "-config", "./openssl.cnf",
           "-infiles", cdir("reqs", "root.csr")]
   run(args)

#-----------------------------------------------------------------------------------------
def createTlsAuthKey():
   print("Generating tls-auth key.")
   run(["openvpn", "--genkey", "secret", cdir("private", "tls-auth.pem")])

#-----------------------------------------------------------------------------------------
def createDHParam():
   print("Generating dhparam.")
   run(["openssl", "dhparam", "-out", cdir("private", "dh2048.pem"), "2048"])

#-----------------------------------------------------------------------------------------
def createDbFolders():
   # All CA data should be highly restricted.
   os.makedirs(conf('dir'), 0o700)
   for d in ["certsdb", "private", "pub", "crl", "profiles", "reqs"]:
      os.makedirs(cdir(d), 0o700)

#-----------------------------------------------------------------------------------------
def initCommand():
   if os.path.exists(conf("dir")):
      printErr(f"Folder already exists. Delete '{conf('dir')}' to start over.")
      return -1
   createDbFolders()
   createEmptyFile(cdir("index.txt"))
   initCRL()

   createCAcert()
   createTlsAuthKey()
   createDHParam()

   updateCRL()

#-----------------------------------------------------------------------------------------
def revokeCert(name):
   if not certExists(name): return
   path = cdir("pub", f"{name}.crt")
   
   # Revoke existing.
   run(["openssl", "ca", "-revoke", path, "-config", "openssl.cnf"])
   os.remove(path)

   updateCRL()

#-----------------------------------------------------------------------------------------
def certExists(name):
   path = cdir("pub", f"{name}.crt")
   return os.path.exists(path)

#-----------------------------------------------------------------------------------------
def yesno(prompt):
    reply = input(prompt + " (y/n): ").strip().lower()
    if reply[0] == 'y':
        return True
    if reply[0] == 'n':
        return False
    else:
        return yesno("prompt")

#-----------------------------------------------------------------------------------------
def askToRevoke(name):
   if certExists(name):
      if yesno(f"Certificate for {name} already exists. Revoke it?"):
         revokeCert(name)
         return True
      else:
         return False
   
   return True

#-----------------------------------------------------------------------------------------
def readFile(filename):
   with open(filename, "r") as f:
      return f.read()

#-----------------------------------------------------------------------------------------
def createProfile(name, type):
   repl = {
      "cacert": readFile(cdir("pub", "root.crt")),
      "cert": readFile(cdir("pub", f"{name}.crt")),
      "key": readFile(cdir("private", f"{name}.pem")),
      "ta": readFile(cdir("private", "tls-auth.pem")),
      "dh": readFile(cdir("private", "dh2048.pem")),
      # Will default next to configuration values.
   }
   
   def replfunc(match):
      val = repl.get(match[1], "")
      if not val:
         return conf(match[1])
      return val

   prof = readFile(f"{type}.ovpn.template")
   prof = re.sub(r"{{([^}]+)}}", replfunc, prof)
   with open(cdir("profiles", name + ".ovpn"), "w") as f:
      f.write(prof)

#-----------------------------------------------------------------------------------------
def create(name, ctype):
   if not askToRevoke(name):
      print("Cancelling.")
      return 0
   
   print(f"Generating key and CSR for {name}")
   cmd = [
      "openssl", "req", "-new", "-newkey", "rsa",
      "-keyout", cdir("private", name + ".pem"),
      "-out", cdir("reqs", name + ".csr"),
      "-config", "./openssl.cnf",
      "-subj", getSubjArg(
                  Args.name, Args.country or conf('country'),
                  Args.state or conf('state'),
                  Args.org or conf('organization'),
                  Args.ou or conf('organizational_unit'),
                  Args.email or conf('email'))]
   if Args.nopass:
      cmd += ["-nodes"]
   run(cmd)
   
   if ctype == "server":
      exts = "my_vpn_server_exts"
   elif ctype == "client":
      exts = "my_vpn_client_exts"
   else:
      printErr("Unexpected type.")
      sys.exit(-1)
   
   if conf('crl_url', None):
      # Use alternate extension with CRL distribution endpoint if crl_url is specified.
      exts += "_crl"
      os.environ["OVPNKEYS_CRL"] = "URI:" + conf('crl_url')

   print("Signing certificate.")
   cmd = [
      "openssl", "ca", "-batch",
      "-days", conf('certification_days'),
      "-config", "openssl.cnf",
      "-extensions", exts,
      "-out", cdir("pub", name + ".crt")]
   cmd += ["-infiles", cdir("reqs", name + ".csr")]
   run(cmd)

   createProfile(name, Args.type)

   os.remove(cdir("private", name + ".pem"))
   print("Deleted private key.")
   print("After trasnferring the profile, you should also delete it from the database.")

#-----------------------------------------------------------------------------------------
def createCommand():
   if not Args.name:
      print("--name is required.")
      return -1
   create(Args.name, Args.type)
   return 0

#-----------------------------------------------------------------------------------------
def revokeCommand():
   if not Args.name:
      print("--name is required.")
      return -1
   revokeCert(Args.name)
   return 0

#-----------------------------------------------------------------------------------------
def crlCommand():
   updateCRL()
   return 0

#-----------------------------------------------------------------------------------------
def main():
   loadConfig()
   parseArgs()

   try:
      if Args.type == "init":
         return initCommand()
      elif Args.type == "client":
         return createCommand()
      elif Args.type == "server":
         return createCommand()
      elif Args.type == "crl":
         return crlCommand()
   except subprocess.CalledProcessError as e:
      printErr(f"Calling {e.cmd} resulted in error ret={e.returncode}")
      return -1

if __name__ == '__main__': sys.exit(main())
