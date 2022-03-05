from pymongo import MongoClient
import json
import zipfile
import os

date = [2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2021, 'recent']
path = '/tmp/'

for i in date:
	#download the file
	os.system(f"cd /tmp ; wget -q https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{i}.json.zip")

	#extract
	with zipfile.ZipFile(f"{path}nvdcve-1.1-{i}.json.zip", 'r') as zip_ref:
	    zip_ref.extractall(path)

	#load json file
	f = open(f'{path}nvdcve-1.1-{i}.json')
	team = json.load(f)

	#remove downloaded file
	os.system(f"rm {path}nvdcve-1.1-{i}.json {path}nvdcve-1.1-{i}.json.zip")

	#Creating a pymongo client
	client = MongoClient('localhost', 27017)

	#Getting the database instance
	db = client['try']

	#import json data
	db.i.insert_one(team)


	#Verification
	print("databases name:")
	print(client.list_database_names())
	print("collections name:")
	print(db.list_collection_names())