# Make Zoom API call

import get_jwt

def getUsers (_myJWT):
	import http.client
	conn = http.client.HTTPSConnection("api.zoom.us")

	headers = {
    	'authorization': "Bearer " + _myJWT,
    	'content-type': "application/json"
    	}

	# Get Active Users
	conn.request("GET", "/v2/users?status=active&page_size=30&page_number=1", headers=headers)

	res = conn.getresponse()
	data = res.read()

	print(data.decode("utf-8"))

classInstance = get_jwt.zoom_jwt()
token = classInstance.makeJWT()

getUsers(token)
