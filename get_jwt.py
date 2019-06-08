#
# https://marketplace.zoom.us/docs/guides/authorization/jwt/generating-jwt
#

import json
import base64
import hmac, hashlib


# Zoom API
#zoom_api_key = '6cLMYYY3Q7Cs57tYfVB3sg'
zoom_api_key = ''
#zoom_api_secret = 'iVpHVSfpyru9GtkNpaV7ATSw6DlJ8ovbHE6P'
zoom_api_secret = ''


class zoom_jwt:

    # Initializer / Instance Attributes
	def __init__(self):
		import os
		from dotenv import load_dotenv
		from pathlib import Path  # python3 only

		env_path = Path('./.env').resolve()
		print('\nPath to .env: ', env_path)
		load_dotenv(dotenv_path=env_path, verbose=True)

		self.zoom_api_key = os.environ['ZOOM-API-KEY']
		self.zoom_api_secret = os.environ['ZOOM-API-SECRET']

		if self.zoom_api_key == '':
			raise Exception('initZoomSecrets() --> Zoom API Key cannot be blank.')
		if self.zoom_api_secret == '':
			raise Exception('initZoomSecrets() --> Zoom API Secret cannot be blank.')

	# Python dictionaries follow:
	def getHeaderBase64(self):
		# Header of JSON Web Token
		header_pydict = { "alg":"HS256","typ":"JWT" }
		header_json = json.dumps(header_pydict)
		header_json = header_json.replace(" ", "")   #Remove whitespace, to make compatiable with https://jwt.io/

		# In Python 3.x you need to convert a 'str' object to a 'bytes' object for base64 to encode.
		# You can do that using the str.encode method:
		# Original code:    header_base64 = base64.b64encode(header_json) 
		header_base64 = base64.b64encode(header_json.encode('utf-8'))
		print('\nBase64 Header (str): ' + str(header_base64, 'utf-8'))
		return header_base64

	# JWT Payload (iss = Zoom API Key)
	# Expire 15 minutes from now.
	def calcTimeStamp(self,_minutes=0):
		from datetime import datetime, timedelta
		expire_on = datetime.now() + timedelta(minutes=_minutes)
		expire_on = expire_on + timedelta(microseconds=-expire_on.microsecond)
		# expire_timestamp = 1559902827
		return int(datetime.timestamp(expire_on))


	def getPayloadBase64(self):
		if self.zoom_api_key == '':
			raise Exception('getPayloadBase64() --> Zoom API Key cannot be blank.')
		payload_pydict = { "iss": self.zoom_api_key, "exp": self.calcTimeStamp(15) }
		payload_json = json.dumps(payload_pydict)
		payload_json = payload_json.replace(" ", "")
		payload_base64 = base64.b64encode(payload_json.encode('utf-8'))
		print('Base64 Payload (str): ' + str(payload_base64, 'utf-8'))
		return payload_base64

	def getSecretKeyBase64(self):
		# Change secret to Bytes, then Base-64 encode it.
		secret_bytes =  self.zoom_api_secret.encode('utf-8')

		# Signature should *not* be in Base 64 for Zoom.
		print('Secret in bytes: ', str(secret_bytes, 'utf-8'))
		return secret_bytes

	def makeJWT(self):
		header64 = self.getHeaderBase64()
		payload64 = self.getPayloadBase64()
		secret64 = self.getSecretKeyBase64()

		encoded_string = str(header64, 'utf-8') + '.' + str(payload64, 'utf-8').replace('=','')
		encoded_bytes = encoded_string.encode('utf-8')
		# print('\nEncoded byte string: ', encoded_bytes, '\n')

		# Option 1: Create manually with HMAC
		encoded_jwt_v1 = base64.b64encode(hmac.new(secret64, \
			msg=encoded_bytes, digestmod=hashlib.sha256).digest(), altchars = '-_'.encode('utf-8'))
		
		encoded_jwt_v1 = str(encoded_jwt_v1, 'utf-8').replace('=','')
		
		print("Signature Version 1, manual HMAC: ", encoded_jwt_v1, '\n')

		print("JWT = ", encoded_string + '.' + encoded_jwt_v1)
		return encoded_string + '.' + encoded_jwt_v1



# Option 2:  Cannot use https://github.com/jpadilla/pyjwt, because it *only* accepts Objects
#encoded_jwt_v2 = jwt.encode( encoded_bytes, zoom_api_secret, algorithm='HS256')
#print("Version 2, JWT library:", encoded_jwt_v2)

# Option 3: Gives a completely wrong answer (somehow)
#encoded_jwt_v3 = jws.sign(encoded_bytes, zoom_api_secret_encode, algorithm='HS256').replace('=','')
#signature_v3 = encoded_jwt_v3.split('.')[2]
#print("Signature Version 3, python-jose: ", signature_v3)
