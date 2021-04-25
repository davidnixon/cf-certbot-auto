
#!/bin/bash
echo $CERTBOT_DOMAIN
set | grep CERTBOT # debugging

# https://certbot.eff.org/docs/using.html#certbot-command-line-options

# Get your API key from https://developer.godaddy.com/keys
API_KEY=$GODADDY_KEY

# DELETE TXT Record in case it exists
curl -X DELETE "https://api.godaddy.com/v1/domains/$CERTBOT_DOMAIN/records/TXT/_acme-challenge" \
  -H  "accept: application/json" \
  -H  "Authorization: sso-key $API_KEY"

# Create TXT record
curl -X PATCH "https://api.godaddy.com/v1/domains/$CERTBOT_DOMAIN/records" \
  -H  "accept: application/json" \
  -H  "Content-Type: application/json" \
  -H  "Authorization: sso-key $API_KEY" \
  -d "[  {    \"data\": \"$CERTBOT_VALIDATION\",    \"name\": \"_acme-challenge\",    \"ttl\": 3600,    \"type\": \"TXT\"  }]"

# Verify GoDaddy created it
curl -X GET "https://api.godaddy.com/v1/domains/$CERTBOT_DOMAIN/records/TXT/_acme-challenge" \
  -H  "accept: application/json" \
  -H  "Authorization: sso-key $API_KEY"

# Sleep to make sure the change has time to propagate over to DNS
sleep 60
