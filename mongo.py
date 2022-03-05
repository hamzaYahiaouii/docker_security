from pymongo import MongoClient
import json
import zipfile
import os

date = [2002, 2003, 2004, 2005, 2006, 2007]
#download the file
os.system("cd /tmp ; wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip")

#extract
with zipfile.ZipFile("/tmp/nvdcve-1.1-2021.json.zip", 'r') as zip_ref:
    zip_ref.extractall("/tmp")

#load json file
f = open('/tmp/nvdcve-1.1-2021.json')
team = json.load(f)

#remove downloaded file
os.system("rm /tmp/nvdcve-1.1-2021.json /tmp/nvdcve-1.1-2021.json.zip")

#Creating a pymongo client
client = MongoClient('localhost', 27017)

#Getting the database instance
db = client['try']
print("Database created........")

#import json data
db.coll2.insert_one(team)

#Verification
print("databases name")
print(client.list_database_names())
print("collections name")
print(db.list_collection_names())