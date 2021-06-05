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

DEBUG = 1

IBMCLOUD='/usr/local/bin/ibmcloud'

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
            
    def get_cert_metadata(self):
        ''' Get metadata for the cert in the payload '''
        payload = self.get_payload()
        self.certmanager_auth()
        
        for cert in payload['certificates']:
            cert_crn_encoded = urllib.parse.quote(cert['cert_crn'], safe='')
            
            url = self.endpoint + ("/v1/certificate/%s/metadata" % cert_crn_encoded)
            response = requests.get(url,
                             headers=self.auth_headers)

            response.raise_for_status()
            print (response.json())

    def invoke_certbot(self, domains, dryrun=False):
        '''use command line + DNS hook to generate certificate with '''
        env=os.environ.copy()
        env["EMAIL"] = self.email
        env["GODADDY_KEY"] = self.godaddy_key
    
        cmd_line = ["certbot", "certonly",
                    "--config-dir", "./config",
                    "--work-dir", "./work",
                    "--logs-dir", "./log",
                    "--agree-tos",
                    "-m", self.email,
                    "--non-interactive",
                    "--manual",
                    "--preferred-challenges", "dns",
                    "--manual-auth-hook", "./godaddy.sh",
                    "-d", domains
                    ]
        if dryrun:
            cmd_line.append("--dry-run")
            
        certbot_process = subprocess.run(cmd_line, 
                                         env=env,
                                         cwd=self.hook_path,
                                         check=True,
                                         stdout=subprocess.PIPE,
                                         encoding="utf-8")
        self.message['certbot'] = certbot_process.stdout

    def certbot_cert(self):
        ''' Generate Let's encrypt for for the certs in the payload '''
        payload = self.get_payload()
        self.certmanager_auth()
        
        self.cf_login()
        for cert in payload['certificates']:
            # print(json.dumps(cert["domains"], indent=2))
            print (cert["domains"])
            cert_name = cert["name"]
            
            self.invoke_certbot(cert["domains"], dryrun=False)
    
            cert_crn_encoded = urllib.parse.quote(cert['cert_crn'], safe='')
    
            if self.cf_list_cert(cert_name):
                self.cf_delete_cert(cert_name)
            self.cf_upload_cert(cert_name)
            self.upload_cert(cert_name, cert_crn_encoded)
        
        self.cf_logout()

                    
    def self_signed_cert(self, domain):
        ''' create a self-signed cert for testing '''
        
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
        print (response.json())

    def cf_login(self):
        '''Login to ibmcloud cf'''
        if self.cf_logged_in:
            return
        
        cmd_line = [IBMCLOUD, 'login', 
                    '--apikey', self.ibm_apikey,
                    '-r', self.region]
        print (" ".join(cmd_line))
        ic_cli = subprocess.run(cmd_line, 
                                cwd=self.hook_path,
                                check=True,
                                stdout=subprocess.PIPE,
                                encoding="utf-8")
        print (ic_cli.stdout)
        cmd_line = [IBMCLOUD, 'target', 
                    '-o', self.cf_org,
                    '--cf-api', self.cf_endpoint ]
        ic_cli = subprocess.run(cmd_line, 
                                cwd=self.hook_path,
                                check=True,
                                stdout=subprocess.PIPE,
                                encoding="utf-8")
        print (ic_cli.stdout)
        self.cf_logged_in = True
    
    def cf_logout(self):
        ''' Logout of IBM Cloud / CF '''
        cmd_line = [IBMCLOUD, 'logout']
        print (" ".join(cmd_line))
        ic_cli = subprocess.run(cmd_line, 
                                cwd=self.hook_path,
                                check=True,
                                stdout=subprocess.PIPE,
                                encoding="utf-8")
        print (ic_cli.stdout)
        
    def cf_list_domains(self):
        ''' List domains in the org 
        '''
        self.cf_login()

        cmd_line = [IBMCLOUD, 'app', 'domains']
        print (" ".join(cmd_line))
        ic_cli = subprocess.run(cmd_line, 
                                cwd=self.hook_path,
                                check=True,
                                stdout=subprocess.PIPE,
                                encoding="utf-8")
        print (ic_cli.stdout)

    def cf_list_cert(self, domain):
        '''List certificate of the cf domain
        https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_commands_apps#cf-list-domain-cert
        '''
        found = True
        self.cf_login()
        
        try:        
            cmd_line = [IBMCLOUD, 'app', 
                        'domain-cert', domain
                         ]
            print (" ".join(cmd_line))
            ic_cli = subprocess.run(cmd_line, 
                                    cwd=self.hook_path,
                                    check=True,
                                    stdout=subprocess.PIPE,
                                    encoding="utf-8")
            print (ic_cli.stdout)
        except Exception as inst:
            found = False
            print(inst)
        
        return found
    def cf_upload_cert(self, domain):
        '''Uplaod a new certificate to the cf org
        https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_commands_apps#cf-add-domain-cert
        '''
        self.cf_login()
        
        try:
            cmd_line = [IBMCLOUD, 'app', 
                        'domain-cert-add', domain,
                        '-c', os.path.join('./config/live', domain, 'fullchain.pem'),
                        '-k', os.path.join('./config/live', domain, 'privkey.pem')
                         ]
            print (" ".join(cmd_line))
            ic_cli = subprocess.run(cmd_line, 
                                    cwd=self.hook_path,
                                    check=True,
                                    stdout=subprocess.PIPE,
                                    encoding="utf-8")
            print (ic_cli.stdout)
        except Exception as inst:
            print(inst)

    def cf_delete_cert(self, domain):
        '''Delete a certificate from the cf org
        https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_commands_apps#cf-remove-domain-cert
        '''
        self.cf_login()
        
        try:        
            cmd_line = [IBMCLOUD, 'app', 
                        'domain-cert-remove', '--force', 
                        domain
                        ]
            print (" ".join(cmd_line))
            ic_cli = subprocess.run(cmd_line, 
                                    cwd=self.hook_path,
                                    check=True,
                                    stdout=subprocess.PIPE,
                                    encoding="utf-8")
            print (ic_cli.stdout)
        except Exception as inst:
            print(inst)

    
# def get_certmanager_info(params):
    # '''Interact with the IBM certificate manager'''
    #
    # # get an auth token
    # headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # data= {
        # "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
        # "apikey": params["ibm_apikey"]
    # }
    # response = requests.post('https://iam.cloud.ibm.com/identity/token',
                             # data=data,
                             # headers=headers)
    # response.raise_for_status()
    # access_token = response.json()["access_token"]
    # token_type = response.json()["token_type"]
    #
    # # get a list of certificates
    # headers = { "Authorization": token_type + " " + access_token}
    # crn = urllib.parse.quote(params["service_instance_crn"], safe='')
    # cert_url = params["endpoint"] + ("/v3/%s/certificates" % crn)
    # payload = {
        # "order": "expires_on",
        # "page_number":0,
        # "page_size":100
    # }
    # response = requests.get(cert_url,
                            # headers=headers,
                            # params=payload)
    # response.raise_for_status()
    # certificates = response.json()["certificates"]
    # for cert in certificates:
        # print(cert["name"])      
    
    
def main(params):
    manager =  CertificateManagerLetsGoCf(params)
    if manager.error:
        return manager.message
    
    payload = manager.get_payload()
    # Event types: https://cloud.ibm.com/docs/certificate-manager?topic=certificate-manager-notifications-event-types
    # test_notification_channel - test
    # cert_about_to_expire_reimport_required
    # cert_expired_reimport_required
    print(payload["event_type"])
    
    if payload["event_type"] == 'cert_about_to_expire_reimport_required' or payload["event_type"] == 'cert_expired_reimport_required':
        #manager.get_cert_metadata()
        #manager.upload_cert()
        # manager.self_signed_cert('davidwnixon.com')
        manager.certbot_cert()
        
    
    return manager.message

    # manager.self_signed_cert('davidwnixon.com')
    # manager.cf_login()
    # if manager.cf_list_cert('davidwnixon.com'):
        # manager.cf_delete_cert('davidwnixon.com')
    # manager.cf_upload_cert('davidwnixon.com')
    # manager.upload_cert('davidwnixon.com')
    # # manager.cf_list_domains()
    # manager.cf_logout()
    #
    # return manager.message


    # hook_path = "/home/app"
    # if "app_path" in params:
        # hook_path = params["app_path"]
        #
    # env=os.environ.copy()
    # env["EMAIL"] = params["email"]
    # env["GODADDY_KEY"] = params["godaddy_key"]
    #
    # cmd_line = ["certbot", "certonly",
                # "--config-dir", "./config",
                # "--work-dir", "./work",
                # "--logs-dir", "./log",
                # "--agree-tos",
                # "-m", params["email"],
                # "--non-interactive",
                # "--manual",
                # "--preferred-challenges",
                # "dns",
                # "--manual-auth-hook", "./godaddy.sh",                
                # "-d", params["cert_domain"]]
    # if payload["event_type"] == "test_notification_channel":
        # cmd_line.append("--dry-run")
    # certbot_process = subprocess.run(cmd_line, 
                                     # env=env,
                                     # cwd=hook_path,
                                     # check=True,
                                     # stdout=subprocess.PIPE,
                                     # encoding="utf-8")
                                     #
    # upload new certificate
    
    
    # return {'certbot':certbot_process.stdout}


