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
import requests
import urllib.parse
import jwt
import json
import datetime
from requests.auth import HTTPBasicAuth
import base64
import time

DEBUG = 1
EXPIRING_SOON = 15
FORCE_RUN = False

IBMCLOUD='/usr/local/bin/ibmcloud'
CERTBOT='/usr/local/bin/certbot'

class CertificateData:
    '''data about a particular certificate'''
    def __init__(self, domain_name, cn, guid):
        self.domain_name = domain_name
        self.cn = cn
        self.guid = guid
        
class CertificateManagerLetsGoCf:
    ''' Manage the steps need to renew a certificate
    1. Get the payload from IBM certificate manager
    2. Based on info from the payload, call certbot to create a new certificate
    3. Upload the new certificate to IBM certificate manager
    4. Upload the certificate to Cloud Foundry
    '''
    def __init__(self, params):
        # make sure we have what we need for success
        self.error = False
        self.message = {'ok': True}

        if not 'data' in params:
            self.error = True
            self.message =  {'ok': False, "message": "missing required input", 'missing': ['data']}
        if not 'service_instance_crn' in params:
            self.error = True
            if self.message['ok']:
                self.message =  {'ok': False, "message": "missing required input", 'missing': ['service_instance_crn']}
            else:
                self.message['missing'].append('service_instance_crn')
        if not 'endpoint' in params:
            self.error = True
            if self.message['ok']:
                self.message =  {'ok': False, "message": "missing required input", 'missing': ['endpoint']}
            else:
                self.message['missing'].append('endpoint')
        if not 'email' in params:
            self.error = True
            if self.message['ok']:
                self.message =  {'ok': False, "message": "missing required input", 'missing': ['email']}
            else:
                self.message['missing'].append('email')
        if not 'godaddy_key' in params:
            self.error = True
            if self.message['ok']:
                self.message =  {'ok': False, "message": "missing required input", 'missing': ['godaddy_key']}
            else:
                self.message['missing'].append('godaddy_key')
        if not 'ibm_apikey' in params:
            self.error = True
            if self.message['ok']:
                self.message =  {'ok': False, "message": "missing required input", 'missing': ['ibm_apikey']}
            else:
                self.message['missing'].append('ibm_apikey')
        if not 'region' in params:
            self.error = True
            if self.message['ok']:
                self.message =  {'ok': False, "message": "missing required input", 'missing': ['region']}
            else:
                self.message['missing'].append('region')


        if not 'cf_org' in params:
            self.error = True
            if self.message['ok']:
                self.message =  {'ok': False, "message": "missing required input", 'missing': ['cf_org']}
            else:
                self.message['missing'].append('cf_org')
        if not 'cf_endpoint' in params:
            self.error = True
            if self.message['ok']:
                self.message =  {'ok': False, "message": "missing required input", 'missing': ['cf_endpoint']}
            else:
                self.message['missing'].append('cf_endpoint')
        self.hook_path = "/home/app"
        if "app_path" in params:
            self.hook_path = params["app_path"]

        if not self.error:
            self.data = params['data']
            self.service_instance_crn = params['service_instance_crn']
            self.endpoint = params['endpoint']
            self.email = params['email']
            self.godaddy_key = params['godaddy_key']
            self.ibm_apikey = params['ibm_apikey']
            self.region = params['region']
            self.cf_org = params['cf_org']
            self.cf_endpoint = params['cf_endpoint']

        self.public_key_str = ''
        self.payload = None
        self.auth_headers = None
        self.cf_auth_headers = None
        self.cf_logged_in = False

    def get_certmanager_publicKey(self):
        '''Get Public key to decrypt payload'''
        if self.public_key_str == '':
            crn_encoded = urllib.parse.quote(self.service_instance_crn, safe='')

            public_key_url = self.endpoint + ("/v1/instances/%s/notifications/publickey" % crn_encoded)
            response = requests.get(public_key_url, params={'keyFormat':'pem'})
            response.raise_for_status()
            response_json = response.json()
            public_key_str = response_json['publicKey']
            #print(response_json['publicKey'])
            self.public_key_str = public_key_str

        return self.public_key_str

    def get_payload(self):
        ''' Get the JWT payload from the data'''
        if not self.payload:
            public_key = self.get_certmanager_publicKey()

            alg = ["RS256", "RS512"]
            self.payload = jwt.decode(self.data, public_key, algorithms=alg)
            if DEBUG > 1:
                print(json.dumps(self.payload, indent=2))

        return self.payload

    def certmanager_auth(self):
        ''' set the headers for the cert manager API '''
        # get an auth token
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data= {
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": self.ibm_apikey
            }
        response = requests.post('https://iam.cloud.ibm.com/identity/token',
                             data=data,
                             headers=headers)
        response.raise_for_status()

        access_token = response.json()["access_token"]
        token_type = response.json()["token_type"]
        self.auth_headers = { "Authorization": token_type + " " + access_token}

    def cf_auth(self):
        ''' set the headers for the Cloud Foundry API '''
        if self.cf_auth_headers == None:
            # get the authorization end point
            url = self.cf_endpoint + '/v2/info'
            response = requests.get(url)
            if DEBUG > 2:
                print ('cf info', json.dumps(response.json(), indent=2))                        
            response.raise_for_status()
            
            authorization_endpoint = response.json()['authorization_endpoint']
                        
            # get an auth token
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            
            auth = HTTPBasicAuth('cf', '')
            url = authorization_endpoint + '/oauth/token'
            data = {
                "grant_type": "password",
                "username": "apikey",
                "password": self.ibm_apikey
                }
            response = requests.post(url, headers=headers, data=data, auth=auth)
            if DEBUG > 2:
                print ('cf login', json.dumps(response.json(), indent=2))                        
            response.raise_for_status()
            
            access_token = response.json()["access_token"]
            token_type = response.json()["token_type"]
            self.cf_auth_headers = { "Authorization": token_type + " " + access_token}
            if DEBUG > 2:
                print ('cf auth', json.dumps(self.cf_auth_headers, indent=2))                        
            

    def list_certs(self):
        '''List certificates'''
        self.certmanager_auth()

        inst_crn_encoded = urllib.parse.quote(self.service_instance_crn, safe='')
        url = self.endpoint + ("/v3/%s/certificates/" % inst_crn_encoded)
        response = requests.get(url, headers=self.auth_headers)
        response.raise_for_status()
        if DEBUG > 1:
            print (response.json())

        expiring_soon = []
        for cert in response.json()['certificates']:
            if DEBUG > 1:
                print(json.dumps(cert, indent=2))
                            
            if cert["issuer"].find('Encrypt') > -1:
                # print(json.dumps(cert, indent=2))
                ms = cert["expires_on"]
                expires = datetime.date.fromtimestamp(ms/1000.0)
                now = datetime.date.today()
                days = (expires - now).days
                if days < EXPIRING_SOON:
                    cert['cert_crn'] = cert["_id"]
                    expiring_soon.append(cert)
                if DEBUG > 0:
                    print("%s expires in %d days" % (cert["name"], days))

        if DEBUG > 1:
            print(json.dumps(expiring_soon, indent=2))
        return expiring_soon

    def get_cert_metadata(self):
        ''' Get metadata for the cert in the payload '''
        self.certmanager_auth()

        inst_crn_encoded = urllib.parse.quote(self.service_instance_crn, safe='')
        url = self.endpoint + ("/v3/%s/certificates/" % inst_crn_encoded)
        response = requests.get(url, headers=self.auth_headers)
        response.raise_for_status()
        if DEBUG > 1:
            print (response.json())

        certificates = response.json()['certificates']
        for cert in certificates:
            if DEBUG > 0:
                print(json.dumps(cert, indent=2))
                            
            ms = cert["expires_on"]
            expires = datetime.date.fromtimestamp(ms/1000.0)
            now = datetime.date.today()
            days = (expires - now).days
            if DEBUG > 0:
                print("%s expires in %d days" % (cert["name"], days))

            cert_id = urllib.parse.quote(cert["_id"], safe='')
            url = self.endpoint + ("/v1/certificate/%s/metadata" % cert_id)
            response = requests.get(url, headers=self.auth_headers)
            response.raise_for_status()
            if DEBUG > 0:
                print (json.dumps(response.json(), indent=2))
        
    def invoke_certbot(self, domains, dryrun=False):
        '''use command line + DNS hook to generate certificate with '''

        try:
            print ("invoke_certbot", domains)
            if isinstance(domains, str):
                domain_str = domains
            else:
                domain_str = domains[0]
                
            env=os.environ.copy()
            env["EMAIL"] = self.email
            env["GODADDY_KEY"] = self.godaddy_key

            cmd_line = [CERTBOT, "certonly",
                        "--config-dir", "./config",
                        "--work-dir", "./work",
                        "--logs-dir", "./log",
                        "--agree-tos",
                        "-m", self.email,
                        "--non-interactive",
                        "--manual",
                        "--preferred-challenges", "dns",
                        "--manual-auth-hook", "./godaddy.sh",
                        "-d", domain_str
                        ]
            if dryrun:
                cmd_line.append("--dry-run")

            if DEBUG > 0:
                print (" ".join(cmd_line))

            certbot_process = subprocess.run(cmd_line,
                                             env=env,
                                             cwd=self.hook_path,
                                             check=True,
                                             stdout=subprocess.PIPE,
                                             encoding="utf-8")
            self.message['certbot'] = certbot_process.stdout
            if DEBUG > 0:
                print (certbot_process.stdout)
        except Exception as inst:
            print("Error running certbot", inst)

    def self_signed_cert(self, domain):
        ''' create a self-signed cert for testing '''

        if DEBUG > 0:
            print("self_signed_cert", domain)

        from OpenSSL import crypto

        output_dir = os.path.join(self.hook_path, 'config/live', domain)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        commonName="*." + domain
        countryName="US"
        validityEndInSeconds=10*24*60*60
        KEY_FILE = os.path.join(self.hook_path, 'config/live', domain, 'privkey.pem')
        CERT_FILE=os.path.join(self.hook_path, 'config/live', domain, 'fullchain.pem')
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = self.email
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')
        
        with open(CERT_FILE, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(KEY_FILE, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


        if DEBUG > 1:
            print (crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))


    def upload_cert(self, domain, cert_crn_encoded):
        '''Upload to the IBM certificate manager'''

        self.certmanager_auth()
        headers = self.auth_headers
        headers['Content-Type'] = 'application/json'
        fullchain_path = os.path.join(self.hook_path, 'config/live', domain, 'fullchain.pem')
        privkey_path = os.path.join(self.hook_path, 'config/live', domain, 'privkey.pem')

        with open(fullchain_path) as f:
            content = f.read()
        with open(privkey_path) as f:
            priv_key = f.read()

        # example_cert_crn = 'crn:v1:bluemix:public:cloudcerts:us-south:a/30f0a21f77994b9eb414b37300e2ced1:91a17928-da3c-4465-9c4b-f1a6b4dce684:certificate:591fc77d985db6816f4905490f900336'
        # cert_crn_encoded = urllib.parse.quote(example_cert_crn, safe='')

        reimport_url = self.endpoint + "/v1/certificate/" + cert_crn_encoded

        cert_data = {
            'content': content,
            'priv_key': priv_key
            }
        response = requests.put(reimport_url,
                                 data=json.dumps(cert_data),
                                 headers=headers)
        response.raise_for_status()
        if DEBUG > 0:
            print (response.json())

    def cf_list_domains(self):
        ''' List domains in all the orgs
        '''
        self.cf_auth()
        headers = self.cf_auth_headers

        # print shared domains (mybluemix.net, etc)
        url = self.cf_endpoint + "/v2/shared_domains"
        response = requests.get(url, headers=headers)
        if DEBUG > 1:
            print (json.dumps(response.json(), indent=2))
        response.raise_for_status()
        for res in response.json()['resources']:
            print(res["entity"]["name"])
        
        # Get a list of orgs
        url = self.cf_endpoint + "/v2/organizations"
        response = requests.get(url, headers=headers)
        if DEBUG > 1:
            print (json.dumps(response.json(), indent=2))
        response.raise_for_status()
        
        # for each org, list the domains
        for res in response.json()['resources']:
            # print(res["entity"]["name"], res["entity"]['private_domains_url'])
            url = self.cf_endpoint + res["entity"]['private_domains_url']
            domain_resp = requests.get(url, headers=headers)
            if DEBUG > 1:
                print (json.dumps(domain_resp.json(), indent=2))
            domain_resp.raise_for_status()
            for dom in domain_resp.json()['resources']:
                domain_name = dom["entity"]["name"]
                print(dom["entity"]["name"], dom)
                self.cf_list_cert(domain_name)
                
        
    def cf_org_domain(self, domain):
        ''' List domains in all the orgs
        '''
        org = None
        
        self.cf_auth()
        headers = self.cf_auth_headers

        # Get a list of orgs
        url = self.cf_endpoint + "/v2/organizations"
        response = requests.get(url, headers=headers)
        if DEBUG > 1:
            print (json.dumps(response.json(), indent=2))
        response.raise_for_status()
        
        # for each org, list the domains
        for res in response.json()['resources']:
            # print(res["entity"]["name"], res["entity"]['private_domains_url'])
            url = self.cf_endpoint + res["entity"]['private_domains_url']
            domain_resp = requests.get(url, headers=headers)
            if DEBUG > 1:
                print (json.dumps(domain_resp.json(), indent=2))
            domain_resp.raise_for_status()
            for dom in domain_resp.json()['resources']:
                found_domain = dom["entity"]["name"]
                if DEBUG > 1:
                    print(found_domain)
                if found_domain == domain:
                    if DEBUG > 1:
                        print(res["entity"]["name"], res["metadata"]["guid"])
                    org = res["metadata"]["guid"]
                    
        return org
        
    def cf_list_cert(self, domain):
        '''List certificate of the cf domain
        https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_commands_apps#cf-list-domain-cert
        https://api.us-east.cf.cloud.ibm.com
        GET /conapi/domains/certificate/summary/zoenixon.com?region=us-south
        '''
        found = True

        try:
            self.certmanager_auth()
            headers = self.auth_headers

            url = "https://cloud.ibm.com/conapi/domains/certificate/summary/" + domain
            params = { "region": self.region}
            response = requests.get(url, headers=headers, params=params)
            if DEBUG > 2:
                print (json.dumps(response.json(), indent=2))
            response.raise_for_status()

        except Exception as inst:
            found = False
            print(inst)

        return found
    
    def cf_upload_cert(self, cert):
        '''Upload a new certificate to the cf org
        https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_commands_apps#cf-add-domain-cert
        
        GET /v2/organizations?q=name%3ANixonHome&region=us-south
        PUT /conapi/domains/certificates/789792a3-fdd8-4c27-a17c-2f76407b1342/davidwnixon.com?region=us-south
        '''

        if DEBUG > 0:
            print ("cf_upload_cert", cert.domain_name)

        try:
            self.certmanager_auth()
            headers = self.auth_headers

            headers['Content-Type'] = 'application/json'
            fullchain_path = os.path.join(self.hook_path, 'config/live', cert.domain_name, 'fullchain.pem')
            privkey_path = os.path.join(self.hook_path, 'config/live', cert.domain_name, 'privkey.pem')

            with open(fullchain_path, "rb") as f:
                content = f.read()
            with open(privkey_path, "rb") as f:
                priv_key = f.read()
            content64 = base64.b64encode(content).decode('ascii')
            priv_key64 = base64.b64encode(priv_key).decode('ascii')

            url = "https://cloud.ibm.com/conapi/domains/certificates/%s/%s" % (cert.guid, cert.domain_name)
            params = { "region": self.region}
            
            cert_data = {
            'cert': content64,
            'key': priv_key64,
            'requireClientCert':False,
            'requestClientCert':False
            }

            for retry in range(3):
                response = requests.put(url, 
                                        data=json.dumps(cert_data), 
                                        headers=headers,
                                        params=params)
                
                if DEBUG > 0:
                    print ("upload response", response.status_code)
                if response.status_code == 409:
                    print(retry, "retrying upload in 20 seconds", response.status_code)
                    time.sleep(20)
                else:
                    break
            
            if DEBUG > 1:
                print (response.text)

            if response.status_code != 404:
                self.message["app_cert_uploaded"] = cert.domain_name
                
            if response.status_code == 200:            
                if DEBUG > 0:
                    print (response.json())

            response.raise_for_status()

        except Exception as inst:
            print(inst)

    def cf_delete_cert(self, cert):
        '''Delete a certificate from the cf org
        https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_commands_apps#cf-remove-domain-cert
        DELETE /conapi/domains/certificates/789792a3-fdd8-4c27-a17c-2f76407b1342/davidwnixon.com?region=us-south
        '''
        if DEBUG > 0:
            print ("cf_delete_cert", cert.domain_name)

        try:
            self.certmanager_auth()
            headers = self.auth_headers

            url = "https://cloud.ibm.com/conapi/domains/certificates/%s/%s" % (cert.guid, cert.domain_name)
            params = { "region": self.region}

            response = requests.delete(url, 
                                       headers=headers,
                                       params=params)
            
            # This happens often. In my testing, almost 100% of the time. If we get an error
            # sleep for about 20 seconds to let the system clean itself up
            if response.status_code == 500:
                time.sleep(20)
            
            if response.status_code != 404:
                self.message["app_cert_deleted"] = cert.domain_name
                
            response.raise_for_status()
            
            if DEBUG > 0:
                print (response.json())            
        except Exception as inst:
            print(inst)

    def cf_check_cert(self, domain_name):
        ''' return CN if this domain_name certification is missing or expired '''
        try:
            self.certmanager_auth()
            headers = self.auth_headers

            url = "https://cloud.ibm.com/conapi/domains/certificate/summary/" + domain_name
            params = { "region": self.region}
            response = requests.get(url, headers=headers, params=params)
                
            if response.status_code != 200:
                if DEBUG > 1:
                    print (response.text)
                 
            if response.status_code == 404:
                return "*." + domain_name

            response.raise_for_status()
            
            cert_data = response.json()
            if DEBUG > 1:
                print (json.dumps(cert_data, indent=2))
            
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

        except Exception as inst:
            print(inst)
            
        return None

        
    def cf_get_expiring_domains(self):
        '''return a list of expiring domains'''

        expiring = []
        self.cf_auth()
        headers = self.cf_auth_headers

        # Get a list of orgs
        url = self.cf_endpoint + "/v2/organizations"
        response = requests.get(url, headers=headers)
        if DEBUG > 1:
            print (json.dumps(response.json(), indent=2))
        response.raise_for_status()
        
        # for each org, list the domains
        for res in response.json()['resources']:
            # print(res["entity"]["name"], res["entity"]['private_domains_url'])
            url = self.cf_endpoint + res["entity"]['private_domains_url']
            domain_resp = requests.get(url, headers=headers)
            if DEBUG > 1:
                print (json.dumps(domain_resp.json(), indent=2))
            domain_resp.raise_for_status()
            guid = res["metadata"]["guid"]
            for dom in domain_resp.json()['resources']:
                domain_name = dom["entity"]["name"]
                expired = self.cf_check_cert(domain_name)
                if expired:
                    
                    expiring.append(CertificateData(domain_name, expired, guid))
        
        return expiring
        
    def certbot_cert(self):
        ''' Generate Let's encrypt for for the expiring certificates '''

        expiring_soon = self.cf_get_expiring_domains()

        for cert in expiring_soon:
            print("updating certificate for %s (%s)" % (cert.domain_name, cert.cn))

            self.self_signed_cert(cert.domain_name)
            # self.invoke_certbot(cert.cn, dryrun=False)

            if self.cf_list_cert(cert.domain_name):
                self.cf_delete_cert(cert)
            self.cf_upload_cert(cert)
        

def main(params):
    manager =  CertificateManagerLetsGoCf(params)
    if manager.error:
        return manager.message

    manager.certbot_cert()
    return manager.message

    payload = manager.get_payload()
    # Event types: https://cloud.ibm.com/docs/certificate-manager?topic=certificate-manager-notifications-event-types
    # test_notification_channel - test
    # cert_about_to_expire_reimport_required
    # cert_expired_reimport_required
    print(payload["event_type"])
    #print(params['data'])

    if payload["event_type"] == 'cert_about_to_expire_reimport_required' or payload["event_type"] == 'cert_expired_reimport_required':
        manager.certbot_cert()

    #If this is a test notification, check to see if anything is expiring "soon"
    if payload["event_type"] == 'test_notification_channel':
        expiring = manager.list_certs()
        manager.certbot_cert(expiring)

    
    return manager.message

if DEBUG:
    test_connection = 'eyJhbGciOiJSUzI1NiJ9.eyJpbnN0YW5jZV9jcm4iOiJjcm46djE6Ymx1ZW1peDpwdWJsaWM6Y2xvdWRjZXJ0czp1cy1zb3V0aDphLzMwZjBhMjFmNzc5OTRiOWViNDE0YjM3MzAwZTJjZWQxOjkxYTE3OTI4LWRhM2MtNDQ2NS05YzRiLWYxYTZiNGRjZTY4NDo6IiwiY2VydGlmaWNhdGVfbWFuYWdlcl91cmwiOiJodHRwczovL2Nsb3VkLmlibS5jb20vc2VydmljZXMvY2xvdWRjZXJ0cy9jcm4lM0F2MSUzQWJsdWVtaXglM0FwdWJsaWMlM0FjbG91ZGNlcnRzJTNBdXMtc291dGglM0FhJTJGMzBmMGEyMWY3Nzk5NGI5ZWI0MTRiMzczMDBlMmNlZDElM0E5MWExNzkyOC1kYTNjLTQ0NjUtOWM0Yi1mMWE2YjRkY2U2ODQlM0ElM0EiLCJldmVudF90eXBlIjoidGVzdF9ub3RpZmljYXRpb25fY2hhbm5lbCIsImNlcnRpZmljYXRlcyI6W3siY2VydF9jcm4iOiJjcm46djE6Ymx1ZW1peDpwdWJsaWM6Y2xvdWRjZXJ0czp1cy1zb3V0aDphLzMwZjBhMjFmNzc5OTRiOWViNDE0YjM3MzAwZTJjZWQxOjkxYTE3OTI4LWRhM2MtNDQ2NS05YzRiLWYxYTZiNGRjZTY4NDpjZXJ0aWZpY2F0ZToxMjM0NTY3OC05MDEyLTM0NTYtNzg5MC0xMjM0NTY3ODkwMTIiLCJkb21haW5zIjoibm90aWZpY2F0aW9uLnRlc3QuY29tIiwiZXhwaXJlc19vbiI6IjIwMjEtMDctMDNUMTI6MDA6MDAuMDAwWiIsIm5hbWUiOiJjZXJ0aWZpY2F0ZSBuYW1lIn1dLCJ2ZXJzaW9uIjo0LCJsYXRlc3RWZXJzaW9uIjo0fQ.nhkBTGGuXt0ZH28x8EKKuFG8sVJAFx-FosKAPjW_hlRK1u0thTV6JMN3bxNQXrRWDHZ1Mktu2h-ojtbmDag33ftd_SKMEMhZVEy-xcBCh5Cv2WEbC0WTqeZV26irvNr2q8NhL53QK3VmyRYr8Kf1BYHfigJ8QWF--ZRtyvwDHO4hMkVsJd_f-fEK7StaCySShgl8Rrv0GlddZLsJnTu6_dz1orZjmoQLkhtYQzG5NQLTj6O8khO9hJF5k2L514tQx1QFw-mIqvZ3pK7BPM-Mi9eRoUn3GFyfQcKH47_JKnxwqMLgRq9Vcskk5kZna_MmsqqzcZ9ORRasvxuiT5Lsrg'
    cert_expiring = "eyJhbGciOiJSUzI1NiJ9.eyJpbnN0YW5jZV9jcm4iOiJjcm46djE6Ymx1ZW1peDpwdWJsaWM6Y2xvdWRjZXJ0czp1cy1zb3V0aDphLzMwZjBhMjFmNzc5OTRiOWViNDE0YjM3MzAwZTJjZWQxOjkxYTE3OTI4LWRhM2MtNDQ2NS05YzRiLWYxYTZiNGRjZTY4NDo6IiwiY2VydGlmaWNhdGVfbWFuYWdlcl91cmwiOiJodHRwczovL2Nsb3VkLmlibS5jb20vc2VydmljZXMvY2xvdWRjZXJ0cy9jcm4lM0F2MSUzQWJsdWVtaXglM0FwdWJsaWMlM0FjbG91ZGNlcnRzJTNBdXMtc291dGglM0FhJTJGMzBmMGEyMWY3Nzk5NGI5ZWI0MTRiMzczMDBlMmNlZDElM0E5MWExNzkyOC1kYTNjLTQ0NjUtOWM0Yi1mMWE2YjRkY2U2ODQlM0ElM0EiLCJldmVudF90eXBlIjoiY2VydF9hYm91dF90b19leHBpcmVfcmVpbXBvcnRfcmVxdWlyZWQiLCJleHBpcnlfZGF0ZSI6MTYyMzI4MzIwMDAwMCwiY2VydGlmaWNhdGVzIjpbeyJjZXJ0X2NybiI6ImNybjp2MTpibHVlbWl4OnB1YmxpYzpjbG91ZGNlcnRzOnVzLXNvdXRoOmEvMzBmMGEyMWY3Nzk5NGI5ZWI0MTRiMzczMDBlMmNlZDE6OTFhMTc5MjgtZGEzYy00NDY1LTljNGItZjFhNmI0ZGNlNjg0OmNlcnRpZmljYXRlOjA3MWRmYzQ1Zjg1NDQyZTBjODQwMTk2MzE3ZTFhZmU2IiwiZG9tYWlucyI6Iiouem9lbml4b24uY29tIiwiZXhwaXJlc19vbiI6MTYyMzI5MzYyODAwMCwibmFtZSI6InpvZW5peG9uLmNvbSJ9XSwidmVyc2lvbiI6NCwibGF0ZXN0VmVyc2lvbiI6NH0.R3yeNBYBVQazEQYPQbJaeZrtxP6cG4SOU8g8Ur1o73-mcj1X4CxL-A8-KqM5fs1lVnCU2cGoqo98rUam1zUtVRv9FHDDBuqqtwgIFMs8aDM70Ni3hPKLRowRrSHeiCVCrobkgaSoqBI3OwUJMXz5A4ZAd9pFDbFY1IlZzsaDy7sRItFSlTNhj1YPdy8GuUfbb5fbYon5S4fefzvEMTW-HRvLr9eMDJ6t8BPbwDLi9EIhP_ffKwDazehP81McVlyMnsiE0JFFmHLatsWg-owXeC6QUutkNrU8MQVvG7yIJu8cPnmiupGWQvWrvdO-SrzmVG3ukFIUr2IEI9L1pTpFxg"

    output = main({
        'email': 'dwnixon@gmail.com',
        'app_path': '/home/davidnixon/projects/certmgr-lets-gd-cf',
        "godaddy_key": "9QEM665EUbJ_5igrikJDzJtcHBDwz5Bk61:MvgDk1ynRGDm4ghREyJtM",
        "cert_domain": "*.zoenixon.com",
        "endpoint": "https://us-south.certificate-manager.cloud.ibm.com/api",
        "service_instance_crn": "crn:v1:bluemix:public:cloudcerts:us-south:a/30f0a21f77994b9eb414b37300e2ced1:91a17928-da3c-4465-9c4b-f1a6b4dce684::",
        "ibm_apikey": "ZYKCcQouX8WFRYJ6ML7DPQ6qT0sH9Jql77cugwVpVnrQ",
        "region": "us-south",
        "cf_org": "NixonHome",
        "cf_endpoint": "https://api.us-south.cf.cloud.ibm.com",
        "data": test_connection,

    })
    print(json.dumps(output, indent=2))
