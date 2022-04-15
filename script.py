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


url = "https://services.nvd.nist.gov/rest/json/cves/1.0/?modStartDate=2021-01-01T13:00:00:000%20UTC%2B01:00&modEndDate=2021-03-31T13:36:00:000%20UTC%2B01:00&keyword=docker"
r = requests.get(url)
for cve in json.loads(r.text)["result"]["CVE_Items"]:
	v = cve
	


client = MongoClient('localhost', 27017)

db = client['vulns']
mycoll = db['1']
db["1"].insert_many([v])

#Verification
print("databases name:")
print(client.list_database_names())
print("collections name:")
print(db.list_collection_names())
x = mycoll.find({},{ "configurations": {'nodes': {"cpe_match": {"cpe23Uri":1, "versionEndIncluding":1 }}}})[0]

print(x)
	











































































"""cluster
docker weave 				weave version
docker compose 			docker inspect img | grep com.docker.compose.version
platform ( bitmani / alpine ... )		docker inspect h2 | grep Image | sed -n 2p
daemon					docker version
runc 					docker-runc --version
"""