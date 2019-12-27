import datetime
from google.cloud import datastore
from flask import Flask, request, make_response, render_template, redirect,  jsonify
from flask_session import Session
import json
import constants
import random
import logging
import string
from json2html import *
from urllib.parse import urlparse, parse_qs
from requests_oauthlib import OAuth2Session
from google.oauth2 import id_token
from google.auth import crypt, jwt
from google.auth.transport import requests



# This disables the requirement to use HTTPS so that you can test locally.
# Taken from lecture code example
import os 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


app = Flask(__name__)
SESSION_TYPE = 'filesystem'
SECRET_KEY= 'random_things'
app.config.from_object(__name__)
Session(app)

client = datastore.Client()
client_id = '153747799768-eq5mp7pki7ddomm84t67nl2jkd6dede5.apps.googleusercontent.com'
client_secret = 'hH-G8zK7tJO-4JjcJ68OZd7e'

redirect_url = 'http://elsomr-jwt.appspot.com/oauth'
scope = ['https://www.googleapis.com/auth/userinfo.email',
			'https://www.googleapis.com/auth/userinfo.profile', 'openid']
oauth = OAuth2Session(client_id, redirect_uri=redirect_url, scope=scope)

def name_is_unique(newName, boat_id):

	query = client.query(kind=constants.boats)
	results = list(query.fetch())
	for boat in results:
		if boat['name'] == newName and str(boat.key.id) != str(boat_id):
			return False
	return True
	
def credentials_are_valid(req):

	print(request.headers)
	try:
		request.headers['Authorization'].split()[1]
		
	except KeyError:
		print("Key error header")
		return None
		
		
	try:
		id_info = id_token.verify_oauth2_token(request.headers['Authorization'].split()[1], req, client_id)
	except ValueError:
		print("\nValueError\n")
		return None
	except TypeError:
		print("\nTypeErrpr\n")
		return None

	return id_info['sub']
	
	
def validInput(content):
	#validate name contains only letters and numbers

	if 'name' in content:
		if not all(x.isalnum() or x.isspace() for x in str(content['name'])):
			print("name")
			return False
		if len(content['name']) > 50:
			return False
	if 'type' in content:
		if not all(x.isalpha() or x.isspace() for x in str(content['type'])):
			return False
		if len(str(content['type'])) > 30:
			return False
	if 'length' in content:
		if not all(x.isnumeric() for x in str(content['length'])):
			return False
		if len(str(content['length'])) > 6:
			return False
	if 'weight' in content:
		if not all(x.isnumeric() for x in str(content['weight'])):
			return False
		if len(str(content['weight'])) > 20:
			return False
	if 'content' in content:
		if not all(x.isalnum() or x.isspace() for x in str(content['content'])):
			return False
		if len(content['content']) > 50:
			return False
	if 'delivery_date' in content:
		if not all(x.isalnum() or x == '-' or x =='/' or x=='\\' for x in str(content['delivery_date'])):
			return False
		if len(content['delivery_date']) > 11:
			return False
	
	return True
	


@app.route('/')
def index():
	auth_url, state = oauth.authorization_url('https://accounts.google.com/o/oauth2/auth',
		access_type = 'offline', prompt = 'select_account')
	print("\nState=")
	print(state)
	print("\n\n")
	render_template("index.html", app_url = auth_url)
	return '<html>\
				<head>\
					<title> Welcome! </title>\
					<link type="text/css" rel="stylesheet" href="{{ url_for("static", filename="style.css") }}">\
				</head>	\
				<body>\
					<h1>Welcome! </h1>\
					<a href="%s" > Click here to authorize access and view token </a>\
					</p>\
				</body>\
			</html>' % auth_url
			
#used for testing only, should not be a published endpoint
@app.route('/clear')
def clear_datastore():
	query = client.query(kind=constants.loads)
	results = list(query.fetch())
	
	for load in results:
		load_key = client.key(constants.loads, int(load.key.id))
		load = client.delete(key=load_key)
		
	query = client.query(kind=constants.boats)
	results = list(query.fetch())
	
	for boat in results:
		boat_key = client.key(constants.boats, int(boat.key.id))
		boat = client.delete(key=boat_key)
		
	return "Please navigate to http://elsomr-final.appspot.com/"

#provides authorization requests and displays token to user
@app.route('/oauth')
def authorize():

	token = oauth.fetch_token('https://accounts.google.com/o/oauth2/token',
		authorization_response=request.url,
		client_secret=client_secret)
	req = requests.Request()
	
	id_info = id_token.verify_oauth2_token(token['id_token'], req, client_id)

	return render_template("userInfo.html", jwt_token = token['id_token']) 

	
	
@app.route('/boats', methods=['POST','GET', 'PATCH', 'PUT', 'DELETE'])
def boats_get_post():
	
	if request.method == "POST":
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
			
		if 'application/json' in request.content_type:
		#get request
			req = requests.Request()
			
			user_sub = credentials_are_valid(req)
			#validate jwt token is valid with an email address
			if (user_sub == None):
				errorMsg= {"Error": "The JWT credentials are invalid or missing"}
				return (json.dumps(errorMsg), 401)
		
			#check that the request has some content in it
			try:
				content = request.get_json() 
			except ValueError:
				#404 error json
				errorMsg = {"Error": "The request object is missing at least one of the required attributes"}
				return (json.dumps(errorMsg), 400)
		
			
			#validate that content attributes are valid 
			if validInput(content) == False:
				#400 error when object attribute has invalid characters or is too long
				errorMsg = {"Error": "One of the request objects has invalid charactores or exceded the character limit"}
				return (json.dumps(errorMsg), 400)	
				
			#check the request content has three objects
			if len(content) != 3 or content["name"] == None or content["type"] == None or content["length"]== None:
				#404 error json
				errorMsg= {"Error": "The request object is missing at least one of the required attributes"}
				return (json.dumps(errorMsg), 400)
				
			#store newly created boat in datastore
			newBoat = datastore.entity.Entity(key=client.key(constants.boats))
			newBoat.update({"name": content["name"], "type": content["type"], "length": content["length"], "loads": [], "owner": user_sub})
			client.put(newBoat)
			
			#format the return JSON message, adding the self attribute
			result = {}
			result={'id': str(newBoat.key.id)}
			for prop in newBoat:
				#no need to iterate through loads since it will be set to None 
				result[prop] = newBoat[prop]
			result["self"] = str(constants.url + "/boats/" + str(newBoat.key.id))


			return (json.dumps(result), 201, {'Content-Type': 'application/json'})
		#if request was not in JSON format
		else:
			errorMsg = {"Error": "Request Header not Acceptable"}
			return (json.dumps(errorMsg), 406)
			
	elif request.method == "GET":
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
			
		query = client.query(kind=constants.boats)
		count= 0
		temp = list(query.fetch())
		for boat in temp:
			count = count + 1
		print(count)

		query = client.query(kind=constants.boats)
		#pagination code taken from lecture and weekly notes
		q_limit = int(request.args.get('limit', '5'))
		q_offset = int(request.args.get('offset','0'))
		l_iterator = query.fetch(limit= q_limit, offset = q_offset)
		pages = l_iterator.pages
		
		results = list(next(pages))
		
		if l_iterator.next_page_token:
			next_offset = q_offset + q_limit
			next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
		else:
			next_url = None
			
		data_arr = []
		data = {}
		#iterating through all ships to format data before returning and adding self attributes
		for e in results:
			data={"id": e.key.id}
			for prop in e:
				#if we are dealing with ship loads, iterate through each load and add self attribute
				if prop == "loads" and e[prop]:
					for id in e[prop]:
						data['loads'] = {}
						data['loads']["id"] = id
						data['loads']["self"] = constants.url + "/loads/" + str(id)
				#id not a load, just set equal to each other
				else:
					data[prop] = e[prop]
			data["self"]= constants.url + "/boats/" + str(e.key.id)
			if next_url:
				data["next"] = next_url
			data['total number of boats'] = count
			data_arr.append(data)
		#returns boat id, need to add status code and other things from documentation here ============================
		return (json.dumps(data_arr), 200, {'Content-Type': 'application/json'})
	
	elif request.method == "PUT" or request.method == "DELETE":
		errorMsg = {"Error": "Request Method Not Allowed on Root URLs"}
		return (json.dumps(errorMsg), 405)
	else:
		#405 error json
		errorMsg = {"Error": "The request method is not allowed"}
		return (json.dumps(errorMsg), 405)
	
@app.route('/boats/<boat_id>', methods=['GET', 'PATCH', 'DELETE', 'PUT'])
def get_patch_or_delete_boat(boat_id):
	if request.method == "GET":
		if 'application/json' in request.accept_mimetypes:
			#gets the specific boat
			boat_key= client.key(constants.boats, int(boat_id))
			boat = client.get(key=boat_key)

			#checks to make sure a boat was returned, if not a boat does not exists at that id
			#also formats error in either html or json based on request
			if boat == None:
				errorMsg = {}
				errorMsg["Error"]= "No boat with this boat_id exists"
				return (json.dumps(errorMsg), 404)

			load_arr = []
			data={'id': str(boat_id)}
			for prop in boat:
				#if we are dealing with ship loads, iterate through each load and add self attribute
				if prop == "loads" and boat[prop]:
					for load in boat['loads']:
						data['loads'] = []
						load_arr.append({"id": load, 'self': constants.url + "/loads/" + \
						str(load)})
					data['loads']=load_arr
				#id not a load, just set equal to each other
				else:
					data[prop] = boat[prop]
			data["self"]= constants.url + "/boats/" + str(boat_id)
			return (json.dumps(data), 200)
		#if user requested an unacceptable reponse content-type
		else:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
			
	elif request.method == "DELETE":
		#fetch the boat data we are about to delete
		boat_key= client.key(constants.boats, int(boat_id))
		boat = client.get(key=boat_key)
		#check that a boat at that id exists
		if boat == None:
			error = {}
			error={"Error": "No boat with this boat_id exists"}
			return (json.dumps(error), 404)
		
		req = requests.Request()
		user_sub = credentials_are_valid(req)
		#verify jwt token is valid
		if (user_sub == None):
			error = {}
			error={"Error": "Invalid or Missing Credentials"}
			return (json.dumps(error), 401)
		
		#return 403 if JWT token does not belong to the correct boat owner
		if (user_sub != boat['owner']):
			error = {}
			error={"Error": "Boat belongs to someone else"}
			return (json.dumps(error), 403)
			
		if boat['loads']:
			#iterate through the recently deleted boats loads setting their carrier values to NULL
			for id in boat['loads']:
				load_key = client.key(constants.loads, int(id))
				load = client.get(key=load_key)
				if str(load['carrier']) == str(boat_id):
					#remove the boat from the load
					for property in load:
						if property == "carrier":
							load[property] = None
						else:
							load[property] = load[property]		
				client.put(load)
				
		#delete the boat
		boat = client.delete(key=boat_key)
		return ('', 204)
		
	elif request.method == "PATCH":
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
			
		#checks that request was JSON format
		if 'application/json' in request.content_type:
			req = requests.Request()
			user_sub = credentials_are_valid(req)
			#verify jwt token is valid
			if (user_sub == None):
				error = {}
				error={"Error": "Invalid or Missing Credentials"}
				return (json.dumps(error), 401)
			

				
			try:
				content = request.get_json()
			except ValueError:
				#404 error json
				error = {}
				error={"Error": "Bad request"}
				return (json.dumps(error), 400)
			
			#validate that content attributes are valid 
			if validInput(content) == False:
				#400 error when object attribute has invalid characters or is too long
				errorMsg = {"Error": "One of the request objects has invalid charactores or exceded the character limit"}
				return (json.dumps(errorMsg), 400)	
	
			# #check that boat name is unique
			# if 'name' in content:
				# if name_is_unique(content['name'], boat_id) == False:
					# #400 error when name is already taken
					# errorMsg = {"Error": "The boat's name is already taken"}
					# return (json.dumps(errorMsg), 403)
						
			#patch the values into the requested boat
			boat_key= client.key(constants.boats, int(boat_id))
			boat = client.get(key=boat_key)
			
			#check that boat exists
			if boat==None:
				error = {}
				error={"Error": "No boat with this boat_id exists"}
				return (json.dumps(error), 404)
			
			#return 403 if JWT token does not belong to the correct boat owner
			if  (user_sub != boat['owner']):
				error = {}
				error={"Error": "Boat belongs to someone else"}
				return (json.dumps(error), 403)
				
				
			propNames = ['name', 'length', 'type']
			#store patched information onto the boat entity
			for prop in content:
				if prop in propNames:
					boat[prop] = content[prop]
			
			client.put(boat)
			
			#format data for return
			data = []
			data={'id':boat.key.id}
			for prop in boat:
				data[prop] = boat[prop]
			data['self']= constants.url + "/boats/" + str(boat.key.id)
			print(data)
			
			#format header for return
			res = make_response(json.dumps(data))
			res.headers.set('Location', data['self'])
			res.mimetype = 'application/json'
			res.status_code = 303
			print(res)
			return (res)
		#if request was not in JSON format
		else:
			errorMsg = {"Error": "Unsupported Media Type"}
			return (json.dumps(errorMsg), 415)
			
	elif request.method == "PUT":
	
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
			
		#check if request is JSON
		if 'application/json' in request.content_type:
			req = requests.Request()
			user_sub = credentials_are_valid(req)
			#verify jwt token is valid
			if (user_sub == None):
				error = {}
				error={"Error": "Invalid or Missing Credentials"}
				return (json.dumps(error), 401)
			
			try:
				content = request.get_json()
			except ValueError:
				#400 error
				error = {}
				error={"Error": "Bad request"}
				return (json.dumps(error), 400)
			
			
				
			#check the request content has the correct three objects
			if len(content) != 3 or content["name"]==None or content["type"] == None or content["length"]== None:
				#404 error json
				error= {}
				error={"Error":"The request object is missing at least one of the required attributes or has too many attributes"}
				return (json.dumps(error), 400)

					
			#validate that content attributes are valid 
			if validInput(content) == False:
				#400 error when object attribute has invalid characters or is too long
				errorMsg = {"Error": "One of the request objects has invalid charactores or exceded the character limit"}
				return (json.dumps(errorMsg), 400)		
				
	# #			check that boat name is unique
			# if name_is_unique(content['name'], boat_id) == False:
				# #400 error when name is already taken
				# errorMsg = {"Error": "The boat's name is already taken"}
				# return (json.dumps(errorMsg), 403)	
				
				
			boat_key= client.key(constants.boats, int(boat_id))
			boat = client.get(key=boat_key)
			
			#check that boat exists
			if boat==None:
				error = {}
				error={"Error": "No boat with this boat_id exists"}
				return (json.dumps(error), 404)
			
			#return 403 if JWT token does not belong to the correct boat owner
			if (user_sub != boat['owner']):
				error = {}
				error={"Error": "Boat belongs to someone else"}
				return (json.dumps(error), 403)
				
			#store each property of the request into the boat
			for property in boat:
				if property in content:
					boat[property] = content[property]

			client.put(boat)
			
			#format data for return
			data = []
			data={'id':boat.key.id}
			for prop in boat:
				data[prop] = boat[prop]
			data['self']= constants.url + "/boats/" + str(boat.key.id)
			
			#format header for return
			res = make_response(json.dumps(data))
			res.headers.set('Location', data['self'])
			res.status_code = 303
			return (res)
			
		#if request was not in JSON format
		else:
			errorMsg = {"Error": "Unsupported Media Type"}
			return (json.dumps(errorMsg), 415)
	else:
		#405 error json
		errorMsg = {"Error": "The request method is not allowed"}
		return (json.dumps(errorMsg), 405)

@app.route('/loads', methods=['POST','GET', 'PUT', 'DELETE'])
def loads_get_post():
	error = {}
	if request.method == "POST":
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
		
		if 'application/json' in request.content_type:
			try:
				content = request.get_json()
			except ValueError:
				error={"Error": "The request object is missing the required number"}
				return (json.dumps(error), 400)
				
			#check the request content has three objects
			if len(content) != 3 or content["weight"]==None or content["content"]==None or content["delivery_date"]==None:
				error={"Error": "The request object is missing the required number"}
				return (json.dumps(error), 400)
				
			#validate that content attributes are valid 
			if validInput(content) == False:
				#400 error when object attribute has invalid characters or is too long
				errorMsg = {"Error": "One of the request objects has invalid charactores or exceded the character limit"}
				return (json.dumps(errorMsg), 400)	
			
			#create new load in datastore
			newLoad = datastore.entity.Entity(key=client.key(constants.loads))
			newLoad.update({"weight": content["weight"], "carrier": None, "content": content["content"], \
			"delivery_date": content["delivery_date"]})
			client.put(newLoad)
			data = {}
			data={'id': newLoad.key.id}
			for prop in newLoad:
				data[prop] = newLoad[prop]
			data['self']= constants.url + "/loads/" + str(newLoad.key.id)
			return (json.dumps(data), 201, {'Content-Type': 'application/json'})
		#if request was not in JSON format
		else:
			errorMsg = {"Error": "Request Header not Acceptable"}
			return (json.dumps(errorMsg), 406)
		
	elif request.method == "GET":
	
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
			

		query = client.query(kind=constants.loads)
		
		#pagination code taken from lecture and weekly notes
		q_limit = int(request.args.get('limit', '5'))
		q_offset = int(request.args.get('offset','0'))
		l_iterator = query.fetch(limit= q_limit, offset = q_offset)
		pages = l_iterator.pages
		
		results = list(next(pages))
		
		if l_iterator.next_page_token:
			next_offset = q_offset + q_limit
			next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
		else:
			next_url = None
			
		data_arr = []
		data = {}

		for load in results:
			data = {"id":load.key.id}
			
			for prop in load:
				#if at the carrier property which has nested data, iterate through that data and fetch boat name
				if prop == "carrier" and load["carrier"]:
					tmp_boat_id = load['carrier']

					#get the boat name that belongs to that id
					boat_key= client.key(constants.boats, int(tmp_boat_id))
					boat = client.get(key=boat_key)
					if (boat) != None:
						#store boat information into data JSON message
						data['carrier'] = {} 
						data[prop]["id"] = tmp_boat_id
						data[prop]["name"] = boat["name"]
						data[prop]["self"] = constants.url + "/boats/" + str(tmp_boat_id)
					#if id was invalid, return load with carrier set to null
					else:
						data[prop] = None
				else:
					data[prop] = load[prop]
			data["self"]= constants.url + "/loads/" + str(load.key.id)
			if next_url:
				data["next"] = next_url
			data_arr.append(data)
			
		return (json.dumps(data_arr), 200, {'Content-Type': 'application/json'})
		
	elif request.method == "PUT" or request.method == "DELETE":
		errorMsg = {"Error": "Request Method Not Allowed on Root URLs"}
		return (json.dumps(errorMsg), 405)
	else:
		errorMsg = {"Error": "Request Method Not Allowed"}
		return (json.dumps(errorMsg), 405)


@app.route('/loads/<load_id>', methods=['GET', 'DELETE', 'PATCH', 'PUT'])
def loads_id_get_delete(load_id):
	error = {}
	if request.method == 'GET':
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
		

		load_key= client.key(constants.loads, int(load_id))
		load = client.get(key=load_key)

		if load == None:
			errorMsg = {}
			errorMsg["Error"]= "No load with this load_id exists"
			return (json.dumps(errorMsg), 404)
		else:
			data = {}
			data={'id': str(load_id)}
			for prop in load:
				if prop == "carrier" and load["carrier"] != None:
					boat_id = load[prop]

					#get the boat name that belongs to that id
					boat_key= client.key(constants.boats, int(boat_id))
					boat = client.get(key=boat_key)
					if (boat) != None:
						data[prop] = {}
						#store boat information into data JSON message
						data[prop]["id"] = boat_id
						data[prop]["name"] = boat["name"]
						data[prop]["self"] = constants.url + "/boats/" + str(boat_id)
					#if id was invalid, return load with carrier set to null
					else:
						data[prop] = None
				else:
					data[prop] = load[prop]
			data["self"]= constants.url + "/loads/" + str(load_id)
			return (json.dumps(data), 200)
	elif request.method == 'DELETE':
		load_key= client.key(constants.loads, int(load_id))
		load = client.get(key=load_key)
		if load == None:
			error={"Error": "No load with this load_id exists"}
			return (json.dumps(error), 404)
		
		#delete the load from the boat hauling it
		if load["carrier"]:
			boat_id = load["carrier"]
			boat_key = client.key(constants.boats, int(boat_id))
			boat = client.get(key=boat_key)
			if boat != None:
				for property in boat:
					if property == "loads":
						if load_id in boat['loads']:
							boat['loads'].remove(load_id)
					else:
						boat[property] = boat[property]
				
			client.put(boat)
				
		load = client.delete(key=load_key)
		
		return ('', 204)
		
	elif request.method == "PATCH":
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
		
		#checks that request was JSON format
		if 'application/json' in request.content_type:
			try:
				content = request.get_json()
			except ValueError:
				#404 error json
				error = {}
				error={"Error": "Bad request"}
				return (json.dumps(error), 400)
			
			#validate that content attributes are valid 
			if validInput(content) == False:
				#400 error when object attribute has invalid characters or is too long
				errorMsg = {"Error": "One of the request objects has invalid charactores or exceded the character limit"}
				return (json.dumps(errorMsg), 400)	
		
			#patch the values into the requested boat
			load_key= client.key(constants.loads, int(load_id))
			load = client.get(key=load_key)
			
			#check that load exists
			if load==None:
				error = {}
				error={"Error": "No load with this load_id exists"}
				return (json.dumps(error), 404)
			
			propNames = ['weight', 'content', 'delivery_date']
			#store patched information onto the boat entity
			for prop in content:
				if prop in propNames:
					load[prop] = content[prop]
			
			client.put(load)
			
			#format data for return
			data = []
			data={'id':load.key.id}
			for prop in load:
				data[prop] = load[prop]
			data['self']= constants.url + "/loads/" + str(load.key.id)
			print(data)
			
			#format header for return
			res = make_response(json.dumps(data))
			res.headers.set('Location', data['self'])
			res.mimetype = 'application/json'
			res.status_code = 303
			print(res)
			return (res)
		#if request was not in JSON format
		else:
			errorMsg = {"Error": "Unsupported Media Type"}
			return (json.dumps(errorMsg), 405)
			
	elif request.method == "PUT":
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
	
		#check if request is JSON
		if 'application/json' in request.content_type:
			try:
				content = request.get_json()
			except ValueError:
				#400 error
				error = {}
				error={"Error": "Bad request"}
				return (json.dumps(error), 400)
			
			
				
			#check the request content has the correct three objects
			if len(content) != 3 or content["weight"]==None or content["content"]==None or content["delivery_date"]==None:
				#404 error json
				error= {}
				error={"Error":"The request object is missing at least one of the required attributes or has too many attributes"}
				return (json.dumps(error), 400)
 
					
			#validate that content attributes are valid 
			if validInput(content) == False:
				#400 error when object attribute has invalid characters or is too long
				errorMsg = {"Error": "One of the request objects has invalid charactores or exceded the character limit"}
				return (json.dumps(errorMsg), 400)			
				
				
			load_key= client.key(constants.loads, int(load_id))
			load = client.get(key=load_key)
			
			#check that load exists
			if load==None:
				error = {}
				error={"Error": "No load with this load_id exists"}
				return (json.dumps(error), 404)
			
			#store each property of the request into the load
			for property in load:
				if property in content:	
					load[property] = content[property]

			client.put(load)
			
			#format data for return
			data = []
			data={'id':load.key.id}
			for prop in load:
				data[prop] = load[prop]
			data['self']= constants.url + "/loads/" + str(load.key.id)
			
			#format header for return
			res = make_response(json.dumps(data))
			res.headers.set('Location', data['self'])
			res.status_code = 303
			return (res)
	else:
		#405 error json
		errorMsg = {"Error": "The request method is not allowed"}
		return (json.dumps(errorMsg), 405)

@app.route('/boats/<boat_id>/loads', methods=['GET'])
def get_load_for_boat(boat_id):
	if request.method == "GET":
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)

		boat_key = client.key(constants.boats, int(boat_id))
		boat = client.get(key=boat_key)
		
		if boat == None:
			error = {"Error": "No boat with this boat_id exists"}
			return(json.dumps(error), 404)

		# req = requests.Request()
		# user_sub = credentials_are_valid(req)
		# #verify jwt token is valid
		# if (user_sub == None):
			# error = {}
			# error={"Error": "Invalid or Missing Credentials"}
			# return (json.dumps(error), 401)
		
		# #return 403 if JWT token does not belong to the correct boat owner
		# if (user_sub != boat['owner']):
			# error = {}
			# error={"Error": "Boat belongs to someone else"}
			# return (json.dumps(error), 403)
			
		#iterate through the boats loads and get all load id
		data = {}
		results = []
		if boat['loads']:		
			#iterate through the id list and call each load to get needed information
			for id in boat['loads']:
				load_key = client.key(constants.loads, int(id))
				load = client.get(key=load_key)
				
				#format data into results dict for returning to user
				data = {"id":load.key.id}
					
				for prop in load:
					#if at the carrier property which has nested data, iterate through that data and fetch boat name
					if prop == "carrier" and load['carrier'] != None:
						data['carrier'] = {}
						data['carrier']['id'] = boat_id
						data['carrier']['name']= boat['name']
						data['carrier']['self'] = constants.url + "/boats/" + str(boat_id)
					else:
						data[prop] = load[prop]
				
				data["self"]= constants.url + "/loads/" + str(load.key.id)
				results.append(data)
				
		return (json.dumps(results), 200, {'Content-Type': 'application/json'})

	else:
		#405 error json
		errorMsg = {"Error": "The request method is not allowed"}
		return (json.dumps(errorMsg), 405)


	
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def boat_load_interations(boat_id, load_id):
	error = {}
	if request.method == 'PUT':
		load_key= client.key(constants.loads, int(load_id))
		load = client.get(key=load_key)
		
		boat_key = client.key(constants.boats, int(boat_id))
		boat = client.get(key=boat_key)
		
		req = requests.Request()
		user_sub = credentials_are_valid(req)
		#verify jwt token is valid
		if (user_sub == None):
			error = {}
			error={"Error": "Invalid or Missing Credentials"}
			return (json.dumps(error), 401)
			
					#check if boat and load id are both valid
		if (boat == None or load == None):
			error={"Error": "The specified boat and/or load don’t exist."}
			return (json.dumps(error), 404)
		
		#return 403 if JWT token does not belong to the correct boat owner
		if (user_sub != boat['owner']):
			error = {}
			error={"Error": "Boat belongs to someone else"}
			return (json.dumps(error), 403)
		

		
		#check if load is already assigned to a boat
		if (load['carrier'] and load['carrier'] != str(boat.key.id)):
			error={"Error": "The load is already assigned to another boat."}
			return (json.dumps(error), 403)
			
		#store the boat in the load carrier property
		for property in load:
			if property == "carrier":
				load['carrier']= boat_id
			# else:
				# load[property] = load[property]
		
		#store the load on the boat loads property
		for property in boat:
			if property == 'loads':
				if boat['loads'] == None:
					boat['loads'] = []
				if load_id not in boat['loads']:
					boat['loads'].append(load_id)
			# else:
				# boat[property] = boat[property]
		

		client.put(load)
		client.put(boat)
		
		return(" ", 204)
		
	elif request.method == 'DELETE':
		#get the data for the load and boat
		load_key= client.key(constants.loads, int(load_id))
		load = client.get(key=load_key)
		
		boat_key = client.key(constants.boats, int(boat_id))
		boat = client.get(key=boat_key)

		#validate that both the load and boat exists and that the load is assigned to the baot
		if (boat == None or load == None or (load_id not in boat['loads'])):
			error={"Error": "No load with this load_id is assigned to a boat with this boat_id"}
			return (json.dumps(error), 404)
		
		req = requests.Request()
		user_sub = credentials_are_valid(req)
		#verify jwt token is valid
		if (user_sub == None):
			error = {}
			error={"Error": "Invalid or Missing Credentials"}
			return (json.dumps(error), 401)
		
		#return 403 if JWT token does not belong to the correct boat owner
		if (user_sub != boat['owner']):
			error = {}
			error={"Error": "Boat belongs to someone else"}
			return (json.dumps(error), 403)		
			
		#iterate through entity and take all existing properties
		for property in load:
			if property == 'carrier':
				#remove ship from load
				load['carrier'] = None
			else:
				load[property] = load[property]
				
		client.put(load)
	

		#iterate through all boat properties 
		for property in boat:
			if property == 'loads':
				boat['loads'].remove(load_id)
			else:
				boat[property]=boat[property]
				
		#put new boat information without load we just removed	
		client.put(boat)
		
		#return success status code
		return('', 204)

	else:
		#405 error json
		errorMsg = {"Error": "The request method is not allowed"}
		return (json.dumps(errorMsg), 405)
		
@app.route('/users/<user_id>/boats', methods=['GET'])
def get_users_boats(user_id):
	
	if request.method == "GET":
	
		req = requests.Request()
		user_sub = credentials_are_valid(req)
		
		#verify jwt token is invalid
		if (user_sub == None):
			error = {}
			error={"Error": "Invalid or Missing Credentials"}
			return (json.dumps(error), 401)
		
		#check that jwt token email matches user id 
		elif (user_sub != user_id):
			error = {}
			error={"Error": "JWT does not match user_id"}
			return (json.dumps(error), 401)
		
		if 'application/json' not in request.accept_mimetypes:
			#406 error json
			errorMsg = {"Error": "Not Allowed, the accept header is not a supported content-type"}
			return (json.dumps(errorMsg), 406)
	
		#query all baots with user id as owner
		query = client.query(kind=constants.boats)
		query.add_filter('owner', '=', user_sub)
		results = list(query.fetch())
		boat_arr = []
		data = {}
		for boat in results:
			data={"id": boat.key.id}
			for prop in boat:
				#if we are dealing with ship loads, iterate through each load and add self attribute
				if prop == "loads" and boat[prop]:
					for load in boat['loads']:
						load_arr = []
						load_arr.append({"id": load, 'self': constants.url + "/loads/" + \
						str(load)})
					data['loads']=load_arr
				#id not a load, just set equal to each other
				else:
					data[prop] = boat[prop]
			data["self"]= constants.url + "/boats/" + str(boat.key.id)
			boat_arr.append(data)

		return (json.dumps(boat_arr), 200, {'Content-Type': 'application/json'})
	else:
		#405 error json
		errorMsg = {"Error": "The request method is not allowed"}
		return (json.dumps(errorMsg), 405)


if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)