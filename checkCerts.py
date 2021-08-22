#
#
# main() will be invoked when you Run This Action.
#
# @param Cloud Functions actions accept a single parameter,
#        which must be a JSON object.
#
# @return which must be a JSON object.
#         It will be the output of this action.
#
#
import os
import subprocess
import json
import datetime
import base64
import time
from OpenSSL import crypto
from requests.auth import HTTPBasicAuth
import requests

DEBUG = 1
EXPIRING_SOON = 15
USE_SELF_SIGNED = False  # debug helper to skip Let's Encrypt and use a self signed certificate instead
# debug helper to dry run the Let's Encrypt certificate creation but skip actually generating a certificate
LETS_CERT_DRYRUN = False

CERTBOT = "/usr/local/bin/certbot"


class CertificateData:
    """data about a particular certificate"""

    def __init__(self, domain_name, cn, guid):
        self.domain_name = domain_name
        self.cn = cn  # pylint: disable=invalid-name
        self.guid = guid


class CfCertbot:
    """Manage the steps need to renew a certificate"""

    def __init__(self, params):
        # make sure we have what we need for success
        self.error = False
        self.message = {"ok": True, "info": []}

        if "email" not in params:
            self.error = True
            if self.message["ok"]:
                self.message = {"ok": False, "message": "missing required input", "missing": ["email"]}
            else:
                self.message["missing"].append("email")
        if "godaddy_key" not in params:
            self.error = True
            if self.message["ok"]:
                self.message = {"ok": False, "message": "missing required input", "missing": ["godaddy_key"]}
            else:
                self.message["missing"].append("godaddy_key")
        if "ibm_apikey" not in params:
            self.error = True
            if self.message["ok"]:
                self.message = {"ok": False, "message": "missing required input", "missing": ["ibm_apikey"]}
            else:
                self.message["missing"].append("ibm_apikey")
        if "region" not in params:
            self.error = True
            if self.message["ok"]:
                self.message = {"ok": False, "message": "missing required input", "missing": ["region"]}
            else:
                self.message["missing"].append("region")
        if "cf_endpoint" not in params:
            self.error = True
            if self.message["ok"]:
                self.message = {"ok": False, "message": "missing required input", "missing": ["cf_endpoint"]}
            else:
                self.message["missing"].append("cf_endpoint")
        self.hook_path = "/home/app"
        if "app_path" in params:
            self.hook_path = params["app_path"]

        if not self.error:
            self.email = params["email"]
            self.godaddy_key = params["godaddy_key"]
            self.ibm_apikey = params["ibm_apikey"]
            self.region = params["region"]
            self.cf_endpoint = params["cf_endpoint"]

        self.public_key_str = ""
        self.payload = None
        self.auth_headers = None
        self.cf_auth_headers = None
        self.cf_logged_in = False

    def ibm_cloud_auth(self):
        """set the headers for the cert manager API"""
        # get an auth token
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": self.ibm_apikey}
        response = requests.post("https://iam.cloud.ibm.com/identity/token", data=data, headers=headers)
        response.raise_for_status()

        access_token = response.json()["access_token"]
        token_type = response.json()["token_type"]
        self.auth_headers = {"Authorization": token_type + " " + access_token}

    def cf_auth(self):
        """set the headers for the Cloud Foundry API"""
        if self.cf_auth_headers is None:
            # get the authorization end point
            url = self.cf_endpoint + "/v2/info"
            response = requests.get(url)
            if DEBUG > 2:
                print("cf info", json.dumps(response.json(), indent=2))
            response.raise_for_status()

            authorization_endpoint = response.json()["authorization_endpoint"]

            # get an auth token
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            auth = HTTPBasicAuth("cf", "")
            url = authorization_endpoint + "/oauth/token"
            data = {"grant_type": "password", "username": "apikey", "password": self.ibm_apikey}
            response = requests.post(url, headers=headers, data=data, auth=auth)
            if DEBUG > 2:
                print("cf login", json.dumps(response.json(), indent=2))
            response.raise_for_status()

            access_token = response.json()["access_token"]
            token_type = response.json()["token_type"]
            self.cf_auth_headers = {"Authorization": token_type + " " + access_token}
            if DEBUG > 2:
                print("cf auth", json.dumps(self.cf_auth_headers, indent=2))

    def invoke_certbot(self, domains, dryrun=False):
        """use command line + DNS hook to generate certificate with
        Lets Encrypt
        """

        try:
            print("invoke_certbot", domains)
            if isinstance(domains, str):
                domain_str = domains
            else:
                domain_str = domains[0]

            env = os.environ.copy()
            env["EMAIL"] = self.email
            env["GODADDY_KEY"] = self.godaddy_key

            cmd_line = [
                CERTBOT,
                "certonly",
                "--config-dir",
                "./config",
                "--work-dir",
                "./work",
                "--logs-dir",
                "./log",
                "--agree-tos",
                "-m",
                self.email,
                "--non-interactive",
                "--manual",
                "--preferred-challenges",
                "dns",
                "--manual-auth-hook",
                "./godaddy.sh",
                "-d",
                domain_str,
            ]
            if dryrun:
                cmd_line.append("--dry-run")

            if DEBUG > 0:
                print(" ".join(cmd_line))

            certbot_process = subprocess.run(
                cmd_line, env=env, cwd=self.hook_path, check=True, stdout=subprocess.PIPE, encoding="utf-8"
            )
            self.message["certbot"] = certbot_process.stdout
            if DEBUG > 0:
                print(certbot_process.stdout)
        except Exception as inst:  # pylint: disable=broad-except
            print("Error running certbot", inst)

    def self_signed_cert(self, domain_name):
        """create a self-signed cert for testing"""

        if DEBUG > 0:
            print("self_signed_cert", domain_name)

        output_dir = os.path.join(self.hook_path, "config/live", domain_name)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        common_name = "*." + domain_name
        country_name = "US"
        validity_end_seconds = 10 * 24 * 60 * 60
        key_file = os.path.join(self.hook_path, "config/live", domain_name, "privkey.pem")
        cert_file = os.path.join(self.hook_path, "config/live", domain_name, "fullchain.pem")
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = country_name
        cert.get_subject().CN = common_name
        cert.get_subject().emailAddress = self.email
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validity_end_seconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, "sha512")

        with open(cert_file, "wt") as f_handle:
            f_handle.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(key_file, "wt") as f_handle:
            f_handle.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

        if DEBUG > 1:
            print(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

    def cf_list_domains(self):
        """List domains in all the orgs
        GET /v2/shared_domains
        GET /v2/organizations
        """
        self.cf_auth()
        headers = self.cf_auth_headers

        # print shared domains (mybluemix.net, etc)
        url = self.cf_endpoint + "/v2/shared_domains"
        response = requests.get(url, headers=headers)
        if DEBUG > 1:
            print(json.dumps(response.json(), indent=2))
        response.raise_for_status()
        for res in response.json()["resources"]:
            print(res["entity"]["name"])

        # Get a list of orgs
        url = self.cf_endpoint + "/v2/organizations"
        response = requests.get(url, headers=headers)
        if DEBUG > 1:
            print(json.dumps(response.json(), indent=2))
        response.raise_for_status()

        # for each org, list the domains
        for res in response.json()["resources"]:
            # print(res["entity"]["name"], res["entity"]['private_domains_url'])
            url = self.cf_endpoint + res["entity"]["private_domains_url"]
            domain_resp = requests.get(url, headers=headers)
            if DEBUG > 1:
                print(json.dumps(domain_resp.json(), indent=2))
            domain_resp.raise_for_status()
            for dom in domain_resp.json()["resources"]:
                domain_name = dom["entity"]["name"]
                print(dom["entity"]["name"], dom)
                self.cf_list_cert(domain_name)

    def cf_org_domain(self, domain_name):
        """return guid of the given CF domain_name organization"""
        org = None

        self.cf_auth()
        headers = self.cf_auth_headers

        # Get a list of orgs
        url = self.cf_endpoint + "/v2/organizations"
        response = requests.get(url, headers=headers)
        if DEBUG > 1:
            print(json.dumps(response.json(), indent=2))
        response.raise_for_status()

        # for each org, list the domains
        for res in response.json()["resources"]:
            # print(res["entity"]["name"], res["entity"]['private_domains_url'])
            url = self.cf_endpoint + res["entity"]["private_domains_url"]
            domain_resp = requests.get(url, headers=headers)
            if DEBUG > 1:
                print(json.dumps(domain_resp.json(), indent=2))
            domain_resp.raise_for_status()
            for dom in domain_resp.json()["resources"]:
                found_domain = dom["entity"]["name"]
                if DEBUG > 1:
                    print(found_domain)
                if found_domain == domain_name:
                    if DEBUG > 1:
                        print(res["entity"]["name"], res["metadata"]["guid"])
                    org = res["metadata"]["guid"]

        return org

    def cf_list_cert(self, domain_name):
        """List certificate of the CF domain_name
        https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_commands_apps#cf-list-domain_name-cert
        https://api.us-east.cf.cloud.ibm.com
        GET /conapi/domains/certificate/summary/example.com?region=us-south
        """
        found = True

        try:
            self.ibm_cloud_auth()
            headers = self.auth_headers

            url = "https://cloud.ibm.com/conapi/domains/certificate/summary/" + domain_name
            params = {"region": self.region}
            response = requests.get(url, headers=headers, params=params)
            if DEBUG > 2:
                print(json.dumps(response.json(), indent=2))
            response.raise_for_status()

        except Exception as inst:  # pylint: disable=broad-except
            found = False
            print(inst)

        return found

    def cf_upload_cert(self, cert):
        """Upload a new certificate to the CF organization
        https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_commands_apps#cf-add-domain-cert
        PUT /conapi/domains/certificates/99999/example.com?region=us-south
        """

        if DEBUG > 0:
            print("cf_upload_cert", cert.domain_name)

        try:
            self.ibm_cloud_auth()
            headers = self.auth_headers

            headers["Content-Type"] = "application/json"
            fullchain_path = os.path.join(self.hook_path, "config/live", cert.domain_name, "fullchain.pem")
            privkey_path = os.path.join(self.hook_path, "config/live", cert.domain_name, "privkey.pem")

            with open(fullchain_path, "rb") as f_handle:
                content = f_handle.read()
            with open(privkey_path, "rb") as f_handle:
                priv_key = f_handle.read()
            content64 = base64.b64encode(content).decode("ascii")
            priv_key64 = base64.b64encode(priv_key).decode("ascii")

            url = "https://cloud.ibm.com/conapi/domains/certificates/%s/%s" % (cert.guid, cert.domain_name)
            params = {"region": self.region}

            cert_data = {"cert": content64, "key": priv_key64, "requireClientCert": False, "requestClientCert": False}

            # In my testing, one or more 409 messages is returned
            for retry in range(5):
                response = requests.put(url, data=json.dumps(cert_data), headers=headers, params=params)

                if DEBUG > 0:
                    print("upload response", response.status_code)
                if response.status_code == 409:
                    print("409: will retry upload %d more times starting in 20 seconds" % (4 - retry))
                    time.sleep(20)
                else:
                    break

            if DEBUG > 1:
                print(response.text)

            if response.status_code != 404:
                self.message["info"].append("app_cert_uploaded " + cert.domain_name)

            if response.status_code == 200:
                if DEBUG > 0:
                    print(response.json())

            response.raise_for_status()

        except Exception as inst:  # pylint: disable=broad-except
            print(inst)

    def cf_delete_cert(self, cert):
        """Delete a certificate from the cf org
        https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_commands_apps#cf-remove-domain-cert
        DELETE /conapi/domains/certificates/999999/example.com?region=us-south
        """
        if DEBUG > 0:
            print("cf_delete_cert", cert.domain_name)

        try:
            self.ibm_cloud_auth()
            headers = self.auth_headers

            url = "https://cloud.ibm.com/conapi/domains/certificates/%s/%s" % (cert.guid, cert.domain_name)
            params = {"region": self.region}

            response = requests.delete(url, headers=headers, params=params)

            # This happens often. In my testing, almost 100% of the time. If we get an error
            # sleep for about 20 seconds to let the system clean itself up
            if response.status_code == 500:
                time.sleep(20)

            if response.status_code != 404:
                self.message["info"].append("app_cert_deleted " + cert.domain_name)

            response.raise_for_status()

            if DEBUG > 0:
                print(response.json())
        except Exception as inst:  # pylint: disable=broad-except
            print(inst)

    def cf_check_cert(self, domain_name):
        """return CN if this domain_name certification is missing or expired"""
        try:
            self.ibm_cloud_auth()
            headers = self.auth_headers

            url = "https://cloud.ibm.com/conapi/domains/certificate/summary/" + domain_name
            params = {"region": self.region}
            response = requests.get(url, headers=headers, params=params)

            if response.status_code != 200:
                if DEBUG > 1:
                    print(response.text)

            if response.status_code == 404:
                if DEBUG > 0:
                    print("%s missing certificate" % (domain_name))
                return "*." + domain_name

            response.raise_for_status()

            cert_data = response.json()
            if DEBUG > 1:
                print(json.dumps(cert_data, indent=2))

            # date string from the cert. i.e. 2021-07-08T01:45:36Z
            not_after = cert_data["cert"]["NotAfter"]
            cert_cn = cert_data["cert"]["Subject"]["CN"]

            # convert the date strung to a python date
            expires = datetime.datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%SZ").date()

            # compare the expiring date to today and retur true if it expres "soon"
            now = datetime.date.today()
            days = (expires - now).days
            if DEBUG > 0:
                if days > 0:
                    print("%s expires in %d days" % (domain_name, days))
                else:
                    print("%s expired %d days ago" % (domain_name, abs(days)))
            if days < EXPIRING_SOON:
                return cert_cn

        except Exception as inst:  # pylint: disable=broad-except
            print(inst)

        return None

    def cf_get_expiring_domains(self):
        """return a list of expiring certificates"""

        self.cf_auth()
        headers = self.cf_auth_headers

        expiring = []  # list of CertificateData objects

        # Get a list of orgs
        url = self.cf_endpoint + "/v2/organizations"
        response = requests.get(url, headers=headers)
        if DEBUG > 1:
            print(json.dumps(response.json(), indent=2))
        response.raise_for_status()

        # for each org, list the domains
        for res in response.json()["resources"]:
            # print(res["entity"]["name"], res["entity"]['private_domains_url'])
            url = self.cf_endpoint + res["entity"]["private_domains_url"]
            domain_resp = requests.get(url, headers=headers)
            if DEBUG > 1:
                print(json.dumps(domain_resp.json(), indent=2))
            domain_resp.raise_for_status()
            guid = res["metadata"]["guid"]
            for dom in domain_resp.json()["resources"]:
                domain_name = dom["entity"]["name"]
                expired = self.cf_check_cert(domain_name)
                if expired:
                    expiring.append(CertificateData(domain_name, expired, guid))

        return expiring

    def certbot_cert(self):
        """Generate SSL certificates for the expiring certificates"""

        expiring_soon = self.cf_get_expiring_domains()

        for cert in expiring_soon:
            if DEBUG > 0:
                print("updating certificate for %s (%s)" % (cert.domain_name, cert.cn))

            if USE_SELF_SIGNED:
                self.self_signed_cert(cert.domain_name)
            else:
                self.invoke_certbot(cert.cn, dryrun=LETS_CERT_DRYRUN)

            if self.cf_list_cert(cert.domain_name):
                self.cf_delete_cert(cert)
            self.cf_upload_cert(cert)


def main(params):
    """This is the IBM function entry point. Find missing/expired/expiring certificates and update them"""
    manager = CfCertbot(params)
    if manager.error:
        return manager.message

    manager.certbot_cert()
    return manager.message
