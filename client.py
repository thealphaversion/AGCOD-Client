import hmac, hashlib, json
from datetime import datetime

import requests

from constants import AMAZON_INCENTIVES_HOST
from exceptions import ClientError

# An enumeration of the types of API
class AGCODServiceOperation:
    ActivateGiftCard, \
    DeactivateGiftCard, \
    ActivationStatusCheck, \
    CreateGiftCard, \
    CancelGiftCard, \
    GetGiftCardActivityPage = range(6)
    
    @classmethod
    def tostring(cls, val):
        for k,v in vars(cls).items():
            if v == val:
                return k

class AWSIncentivesClient:
    def __init__(
        self,
        service: AGCODServiceOperation,
        AMAZON_ACCESS_KEY_ID: str,
        AMAZON_SECRET_KEY: str
    ) -> None:
        # Client params
        self._service = service

        # The constants are lowercase because the signature generation process
        # requires them to be lowercase

        # Static headers used in the request
        self.ACCEPT_HEADER = 'accept'
        self.CONTENT_HEADER = 'content-type'
        self.HOST_HEADER = 'host'
        self.XAMZDATE_HEADER = 'x-amz-date'
        self.XAMZTARGET_HEADER = 'x-amz-target'
        self.AUTHORIZATION_HEADER = 'Authorization'
        self.CONTENT_TYPE = 'application/json'

        # Parameters used in the message header
        self.HOST = AMAZON_INCENTIVES_HOST
        self.PROTOCOL = 'https'
        self.QUERY_STRING = ''
        self.REQUEST_URI = f'/{AGCODServiceOperation.tostring(self._service)}'
        self.SERVICE_TARGET = f'com.amazonaws.agcod.AGCODService.{AGCODServiceOperation.tostring(self._service)}'
        self.HOST_NAME = self.PROTOCOL + '://' + self.HOST + self.REQUEST_URI

        # User and instance parameters
        self.AWS_KEY_ID = AMAZON_ACCESS_KEY_ID
        self.AWS_SECRET_KEY = AMAZON_SECRET_KEY
        self.date_time_string = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        self.date_string = self.date_time_string[:8]

        # Signature calculation related parameters
        self.HMAC_SHA256_ALGORITHM = 'HmacSHA256'
        self.HASH_SHA256_ALGORITHM = 'SHA-256'
        self.AWS_SHA256_ALGORITHM = 'AWS4-HMAC-SHA256'
        self.KEY_QUALIFIER = 'AWS4'
        self.TERMINATION_STRING = 'aws4_request'

        # Service and target (API) parameters
        self.REGION_NAME = 'eu-west-1'
        self.SERVICE_NAME = 'AGCODService'

        # Payload parameters
        self.PARTNER_ID = 'Un7c7'
        self.REQUEST_ID_PREFIX = 'Un7c7'
        self.CURRENCY_CODE = 'GBP'

        # Request parametes
        self.REQUEST_TIMEOUT = 2

    def get_service(self, kind='enum'):
        if kind == 'str':
            return AGCODServiceOperation.tostring(self._service)
        return self._service

    def set_service(self, service: int) -> None:
        self._service = service

    # Used to hash the payload and hash each previous step in the AWS signing process
    def hashstr(self, to_hash):
        return hashlib.sha256(json.dumps(to_hash).encode('utf-8')).hexdigest()

    def hmac_binary(self, data, b_key, out='bytes'):
        if not isinstance(data, bytes):
            data = data.encode('utf-8')
        if not isinstance(b_key, bytes):
            b_key = b_key.encode('utf-8')

        if out == 'string':
            return hmac.new(b_key, data, hashlib.sha256).hexdigest()

        return hmac.new(b_key, data, hashlib.sha256).digest()

    def _build_canonical_request(self, payload):
        # Create a SHA256 hash of the payload, used in authentication
        payload_hash = self.hashstr(payload)

        # Canonical request headers should be sorted by lower case character code
        canonical_request = 'POST\n' \
            + self.REQUEST_URI + '\n' \
            + self.QUERY_STRING + '\n' \
            + self.ACCEPT_HEADER + ':' + self.CONTENT_TYPE + '\n' \
            + self.HOST_HEADER + ':' + self.HOST + '\n' \
            + self.XAMZDATE_HEADER + ':' + '20220114T190157Z' + '\n' \
            + self.XAMZTARGET_HEADER + ':' + self.SERVICE_TARGET + '\n' \
            + '\n' \
            + self.ACCEPT_HEADER + ';' + self.HOST_HEADER + ';' + self.XAMZDATE_HEADER + ';' + self.XAMZTARGET_HEADER + '\n' \
            + payload_hash

            # + self.CONTENT_HEADER + ':' + self.CONTENT_TYPE + '\n' \
        
        return canonical_request

    # Uses the previously calculated canonical request to create a single "String to Sign" for the request
    def _build_string_to_sign(self, canonical_request_hash):
        string_to_sign = self.AWS_SHA256_ALGORITHM + '\n' \
            + self.date_time_string + '\n' \
            + self.date_string + '/' + self.REGION_NAME + '/' + self.SERVICE_NAME + '/' + self.TERMINATION_STRING + '\n' \
            + canonical_request_hash
        
        return string_to_sign

    # This function uses given parameters to create a derived key based on the secret key and parameters related to the call
    def _build_derived_key(self):
        aws_key_signature = self.KEY_QUALIFIER + self.AWS_SECRET_KEY

        # Calculate the derived key
        derived_key = self.hmac_binary(
            self.TERMINATION_STRING, self.hmac_binary(
                self.SERVICE_NAME, self.hmac_binary(
                    self.REGION_NAME, self.hmac_binary(
                        self.date_string, aws_key_signature
                    )
                )
            )
        )
        
        return derived_key

    # signature = HexEncode(HMAC(derived signing key, string to sign))
    def _calculate_signature(self, string_to_sign) -> str:
        derived_key = self._build_derived_key()
        signature = self.hmac_binary(string_to_sign, derived_key, out='string')

        return signature

    # Authorization: algorithm Credential=access key ID/credential scope, SignedHeaders=SignedHeaders, Signature=signature
    def _build_authorization_header(self, signature):
        authorization_value = self.AWS_SHA256_ALGORITHM \
            + ' Credential=' + self.AWS_KEY_ID + '/' \
            + self.date_string + '/' \
            + self.REGION_NAME + '/' \
            + self.SERVICE_NAME + '/' \
            + self.TERMINATION_STRING + ',' \
            + ' SignedHeaders=' + self.ACCEPT_HEADER + ';' \
            + self.CONTENT_HEADER + ';' \
            + self.HOST_HEADER + ';' \
            + self.XAMZDATE_HEADER + ';' \
            + self.XAMZTARGET_HEADER + ',' \
            + ' Signature=' + signature

        return authorization_value

    # Build a dict containing the data to be used to form the request payload
    def _build_request_payload(self, amount, request_id):
        params = {
            'creationRequestId': request_id,
            'partnerId' : self.PARTNER_ID,
            'value': {
                'currencyCode' : self.CURRENCY_CODE,
                'amount' : amount,
            },
        }

        return params

    def _prepare_request_header(self, amount, request_id):
        headers = {
            self.ACCEPT_HEADER: self.CONTENT_TYPE,
            self.HOST_HEADER: self.HOST,
            self.XAMZDATE_HEADER: self.date_time_string,
            self.XAMZTARGET_HEADER: self.SERVICE_TARGET,
        }

        # Build canonical request and its hash
        canonical_request = self._build_canonical_request(self._build_request_payload(amount, request_id))
        print('canonical_request:', canonical_request)
        print('               ')
        canonical_request_hash = self.hashstr(canonical_request)
        print('canonical_request_hash:', canonical_request_hash)
        print('               ')

        # Build string to sign
        string_to_sign = self._build_string_to_sign(canonical_request_hash)
        print('string_to_sign:', string_to_sign)
        print('               ')

        # Create signature
        signature = self._calculate_signature(string_to_sign)
        print('signature:', signature)
        print('               ')

        # Build authorization header
        authorization_header = self._build_authorization_header(signature)
        print('authorization_header:', authorization_header)
        print('               ')

        # Add authorization header to headers
        headers[self.AUTHORIZATION_HEADER] = authorization_header

        print('headers:', headers)

        return headers

    def make_request(self, amount, user_id, lead_id):
        request_id = f'{self.REQUEST_ID_PREFIX}u{user_id}l{lead_id}'
        headers = self._prepare_request_header(amount,request_id)

        try:
            req = requests.Request(
                'POST',
                self.HOST_NAME,
                json=self._build_request_payload(amount, request_id),
                headers=headers,
                # timeout=self.REQUEST_TIMEOUT
            )
            prepared = req.prepare()
            print('            ')
            print('            ')
            self.pretty_print_POST(prepared)
            r = requests.post(
                self.HOST_NAME,
                json=self._build_request_payload(amount, request_id),
                headers=headers,
            )
            print('response status code:', r.status_code)
            print('response test', r.text)
        except requests.Timeout:
            print('ERROR: INCENTIVES: Request timed out')
            return {}

        return req

    def pretty_print_POST(self, req):
        """
        At this point it is completely built and ready
        to be fired; it is "prepared".

        However pay attention at the formatting used in 
        this function because it is programmed to be pretty 
        printed and may differ from the actual request.
        """
        print('{}\n{}\r\n{}\r\n\r\n{}'.format(
            '-----------START-----------',
            req.method + ' ' + req.url,
            '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
            req.body,
        ))