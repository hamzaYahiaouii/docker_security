import requests, json
from datetime import date
from pymongo import MongoClient
import os

mounths = [["01", "03"], ["04", "06"], ["07", "09"], ["10", "12"]]

todays_date = date.today()
years = [ int(todays_date.year) - i  for i in range(10) ]
database = dict()


"""
for year in years:
	for mounth in mounths:
		year = str(year)
		start = mounth[0]
		end = mounth[1]
		url = f"https://services.nvd.nist.gov/rest/json/cves/1.0/?modStartDate={year}-{start}-01T13:00:00:000%20UTC%2B01:00&modEndDate={year}-{end}-31T13:36:00:000%20UTC%2B01:00&keyword=docker"
		req = requests.get(url)
		print(url)
		print(len(req.text))
"""

"""
for i in mounths:
	print(i[0])
r = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=docker")
print(r.text)"""

v=""
url = "https://services.nvd.nist.gov/rest/json/cves/1.0/?modStartDate=2021-01-01T13:00:00:000%20UTC%2B01:00&modEndDate=2021-03-31T13:36:00:000%20UTC%2B01:00&keyword=docker"
r = requests.get(url)
x = json.loads(r.text)["result"]




client = MongoClient('localhost', 27017)

db = client['vulns']
mycoll = db['cve']
db["cve"].insert_many([x])

#Verification
print("databases name:")
print(f"databases name: {client.list_database_names()}")
print(f"collections name: {db.list_collection_names()}")


for cve in mycoll.find({},{ "configurations": {'nodes': {"cpe_match": {"cpe23Uri": 1, "versionEndIncluding":1 }}}}):
	print("-----------------------------------------------------------")
	print(cve)

"""

platform=""
ver=""

mycoll.find({},{ 

	$or: [
		{"configurations.'nodes.cpe_match": {"cpe23Uri": {$regex:plat} , "versionEndIncluding":{$regex:ver}}},
		{"configurations.'nodes.cpe_match.versionStartIncluding": {$exists: true}, "configurations.'nodes.cpe_match": {"cpe23Uri": {$regex:plat} , "versionEndIncluding": {$lt: ver}, "versionStartIncluding": {$gt: ver} }
		 }
	]

})