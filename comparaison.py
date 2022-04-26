import requests, json
from pymongo import MongoClient
import os
import sys
 
daemon_correction = " "
runc_correction = " "
swarm_correction = " "
compose_correction = " "
docker_correction = " "

fault = [0,0,0,0,0]
daemon = { "platform":sys.argv[0] , "version":sys.argv[1] }
runc = { "platform":sys.argv[2] , "version":sys.argv[3] }
swarm = { "platform":sys.argv[4] , "version":sys.argv[5] }
compose = { "platform":sys.argv[6] , "version":sys.argv[7] }
docker = { "platform":sys.argv[8] , "version":sys.argv[9] }

table = [daemon,runc,swarm,compose,docker]

client = MongoClient('localhost', 27017)

db = client['vulns']
mycoll = db['cve']

for i in table:

	query = """{
		$or: [
			{"configurations.nodes.cpe_match": {"cpe23Uri": {$regex:i["platform"]} , "versionEndIncluding": {$regex:i["version"]} } },
			{"configurations.nodes.cpe_match.versionStartIncluding": {$exists: true}, "configurations.nodes.cpe_match": {"cpe23Uri": {$regex:i["platform"]} , "versionEndIncluding": {$lt: i["version"]}, "versionStartIncluding": {$gt: i["version"]} }
			 }
		]

	}"""

	result = mycoll.find(query)
	if result != "":
		f[i-1] = 1
		for cve in result["cve"]:
			print(cve["CVE_data_meta"]["ID"])
			print(cve["description"]["description_data"][0]["value"])
			

if fault[0] = 1:
    print(daemon_correction)
elif fault[1] = 1 :
    print(runc_correction)
if fault[2] = 1 :
    print(swarm_correction)
elif fault[3] = 1 :
    print(compose_correction)
elif fault[4] = 1 :
    print(docker_correction)
else:
	print("[+] Done")
	print("[+] There is no vulnirability in this container")

