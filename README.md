# How to Automate Let's Encrypt SSL certificates for IBM Cloud Foundry

For open source or personal or hobby sites, many developers are very familiar with the free tool [Let’s Encrypt](https://letsencrypt.org/) and the associated tool [certbot](https://certbot.eff.org/) which let you encrypt your site with a SSL certificate. But certbot does not have built-in support to automatically renew when using IBM Cloud Foundry, so custom DevOps automation is needed.

The code here bridges that gap between IBM Cloud Foundry and Let's Encrypt so that you can use Let's Encrypt certificates and automate the renewal of those certificates and deploy them to your Cloud Foundry organization.

## How does it work

The code is deployed as a python script and a docker image for a custom **action** and **trigger** in [IBM Cloud Functions](https://cloud.ibm.com/functions/). The **action's** python script finds all the custom domains for your account in a given region, checks if their certificates are expired or expiring soon, or missing. For those certificates, the code uses certbot to generate new certificates and upload them to your IBM Cloud Foundry organization.

The **trigger** uses `/whisk.system/alarms/alarm` as its feed which enables it to call the **action** twice a day to check your certificates.

## Code sequence for the action

- REST API `GET /v2/organizations`
- for each organization, REST API `GET /v2/organizations/uid/private_domains`
- for each domain, REST API `GET /conapi/domains/certificate/summary/`
- for each required certificate, invoke certbot command line in the custom docker image to generate a new certificate
- for each generated certificate, REST API `DELETE /conapi/domains/certificates/`
- for each generated certificate, REST API `PUT /conapi/domains/certificates`

The code assumes that all the domains and certificates can be managed by the same DNS provider. In this example, they are all managed by GoDaddy. The code would need to be customized to provide inclusion/exclusion rules if different providers needed to be supported.

## Known issues

If the code fails or times out, your site may be left with a missing certificate. Again, the target use is for open source or personal or hobby sites where I think this is an acceptable risk.

Depending on your targeted region, I have found that the deletion and the upload of certificates often does time out. Even though the operation times out, the back-end process does eventually complete successfully. IBM support is aware of this but as of this writing there is no ETA for a permanent solution. If, for instance, the delete times out, your site will be without a certificate until the next time the automation runs. The automation runs by default twice a day so this is an acceptable risk for me. If the upload times out, you will see that the **action** returned an error but eventually the certificate is uploaded.

## Pre-reqs

1. [IBM Cloud account](https://cloud.ibm.com/registration)
1. [IBM Cloud CLI](https://cloud.ibm.com/docs/cli/reference/bluemix_cli/download_cli.html)
   - Also install the Cloud Foundry CLI `ibmcloud cf install`
1. A Cloud Foundry app
1. A custom domain to use with your Cloud Foundry app
1. An API key from GoDaddy

## Quick start

- Login to IBM cloud account cli
- List domains in your account: `ibmcloud cf domains`
  - verify that all the "owned" or "private domains" can be managed by GoDaddy DNS provider
- Deploy the action and trigger

  - Copy the `manifest.template.yaml` file to `manifest.yaml`.
  - Edit the manifest and update the `email` value, `ibm_apikey` value, and the `godaddy_key` value.
  - You _may_ also need to update the `cf_endpoint` and `region` values depending on your preferences.

  Deploy the action and the trigger:

  ```sh
  ibmcloud functions deploy
  ```

- By default the **trigger** runs the **action** twice a day at 03:15 and 06:15

## Notes

### IBM Cloud Foundry

IBM Cloud Foundry offers a no-cost platform as a service (PaaS) where you can host any small website. It is a great serverless option were you can deploy and scale applications without manually configuring and managing servers. You can learn more about it on the [IBM Cloud Foundry site](https://www.ibm.com/cloud/cloud-foundry)

### Let’s Encrypt

[Let’s Encrypt](https://letsencrypt.org/about/) is a free, automated, and open certificate authority (CA), run for the public’s benefit. It is a service provided by the Internet Security Research Group (ISRG).

### Certbot

[Certbot](https://certbot.eff.org/about/) is a free, open source software tool for automatically using Let’s Encrypt certificates on manually-administrated websites to enable HTTPS.

### GoDaddy

The code assumes you are using Godaddy as your DNS provider. The Let's Encrypt certbot actually has much better support for other providers. You can find that list on Certbot's [DNS plugins list](https://certbot.eff.org/docs/using.html#dns-plugins)

Let me know if you adapt this code to use one of those other DNS plugins. I would love to merge that back here. Or if you want some help doing that let me know and I'll see if I can help.

#### GoDaddy API key security

IMHO the security options for GoDaddy API keys are not very robust. You can, of course, generate a GoDaddy API key which you can use to interact with the GoDaddy DNS which is exactly what this code does. Unfortunately, you cannot, as of this writing, scope the API key to **ONLY** interact with the DNS APIs. Your key can do anything! You can use the key to order services, delete services, etc. and so **you must take great care to keep your key safe**. I also recommend you generate a new key often to help prevent any damage a leaked key might do to your account.
https://developer.godaddy.com/getstarted

### IBM Certificate Manager

IBM also has an SSL certificate manager which integrates directly with many of the IBM services. The [IBM Certificate Manager](https://www.ibm.com/cloud/certificate-manager) generate alerts when your certificates are about to expire.You can also order certificates from IBM but there is not currently any integration with either Let's Encrypt (certbot) or with the IBM Cloud Foundry.

## Acknowledgments

Thanks to all on stackoverflow.com for the help in [authenticating with IBM Cloud Foundry REST API](https://stackoverflow.com/questions/64163745/how-to-authenticate-ibm-cloud-function-to-use-ibm-cloud-foundry-api).

## Customizing

Obviously you can edit `checkCerts.py` to customize. You can also edit the `Dockerfile` if you need something different than GoDaddy. You would just need to make your edits and push your new image to Docker hub so that you can use it with your action.

```sh
docker build -t yourname/cf-certbot-auto:yourtag
docker push yourname/cf-certbot-auto:yourtag
```

Edit the `manifest.yaml` and specify your new docker image.

## Questions?

- Is there a nodejs version of this code?
  - No but maybe later. LMK if this is important to you.
- Why is this written in python?
  - I like python this week so ... maybe next week I'll rewrite it in Ruby or Go or maybe [COBOL](https://gnucobol.sourceforge.io/) or [Ada](https://www.gnu.org/software/gnat/)
- Maybe you should use threads?
  - Nah. I only have a few domains. I think probably if this was a thing I would create a flow of actions such that the first actions determined the list of expiring certificates and then farmed those out to an "update" action.
