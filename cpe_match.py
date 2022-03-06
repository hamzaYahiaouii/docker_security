from pymongo import MongoClient
import json
#Creating a pymongo client
myclient = MongoClient("mongodb://localhost:27017/")

mydb = myclient["dockersec"]

mycol = mydb["cve_list"]

with open("/home/hamza/memoire/nvdcve-1.1-2021.json", "r") as f:
   team = json.load(f)
#print(team["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"])
#print(team["CVE_Items"][i]["cve"]["description"]["description_data"][0]["value"])
#print(team["CVE_Items"][i]["cve"]["CVE_data_meta"]["ID"])
# x = mycol.insert_one(team)
i = 0
f = 0
while i < 18715:
	try:
		print(team["CVE_Items"][i]["configurations"]["nodes"][0]["children"][0]["cpe_match"][0]["cpe23Uri"])
		try:
			print(team["CVE_Items"][i]["configurations"]["nodes"][0]["children"][0]["cpe_match"][0]["versionEndExcluding"])
		except:
			pass
		try:
			print(team["CVE_Items"][i]["configurations"]["nodes"][0]["children"][0]["cpe_match"][0]["versionStartExcluding"])
			i = i+1
		except:
			pass
			i = i+1

	except:
		try:
			print(team["CVE_Items"][i]["configurations"]["nodes"][0]["cpe_match"][0]["cpe23Uri"])
			i = i + 1
		except:
			print("there's no data about this vuln")
			i = i+1

print(f)