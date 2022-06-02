from pymongo import MongoClient
import json
import requests
import re
import os
import subprocess


def function(start, end, ver):
    try:
        start = float(start)
        start = f'{start}.0'
    except:
        pass

    start = start.split(".", 1)
    end = end.split(".", 1)
    ver = ver.split(".", 1)
    float(start[0]),float(end[0]),float(ver[0]),float(start[1]),float(end[1]),float(ver[1])
    

    if (start[0] == end[0] == ver[0]) :
        if (start[1] <= ver[1] and end[1] > ver[1]):
            return True 
        else: 
            return False 
    elif (ver[0] == start[0]):
        if (start[1] <= ver[1]): 
            return True
        else:
            return False
    elif (ver[0] == end[0]):
        if (end[1] > ver[1]):
            return True
        else:
            return False
    elif (start[0] <= ver[0] and end[0] > ver[0]):
        return True
    else:
        return False
    



platform = "openshift"
version = "4.5.0"

url = "https://services.nvd.nist.gov/rest/json/cves/1.0/?modStartDate=2019-10-01T13:00:00:000%20UTC%2B01:00&modEndDate=2019-12-31T13:36:00:000%20UTC%2B01:00&keyword=docker"
r = requests.get(url)
x = json.loads(r.text)["result"]
string = "versionStartIncluding"
k = 0
j = 0
while k < len(x["CVE_Items"]):

	f = x["CVE_Items"][k]["configurations"]["nodes"][0]["cpe_match"]
	match = re.search(string, str(f), re.IGNORECASE)
	if not match :
		a = re.search(platform, str(f), re.IGNORECASE)
		b = re.search(version, str(f), re.IGNORECASE)
		if a and b: 
			ID = x["CVE_Items"][k]["cve"]["CVE_data_meta"]["ID"]
			discription = x["CVE_Items"][k]["cve"]["description"]["description_data"][0]["value"]
			score = x["CVE_Items"][k]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
			print("--------------------------------------------")
			print("vulnerability found")
			print("--------------------------------------------")
			print("detail")
			print("--------------------------------------------")
			print(f"id: {ID}")
			print(f"description: {discription}")
			print(f"score: {score}")
			print("--------------------------------------------")
			
			
		else:
			print("not vulnerable")
	else:
		file = open("/tmp/lopo", "w")
		file.write(f"{str(f)}\n")
		file.close()
		os.system("cat /tmp/lopo | grep -o -P '.{0,70}versionStartIncluding.{0,70}' > /tmp/cut")
		#length = os.popen("cat /tmp/cut | wc -l")
		length = subprocess.check_output("cat /tmp/cut | wc -l", shell=True)
		length =  int(length)

		while j < length:
			plat = os.popen(f"cat /tmp/cut | grep {platform}").read()
			commande1 =  f"cat /tmp/cut | cut -d 'S' -f 2 | cut -d \"'\" -f 3 | sed -n {j+1}p"
			#commande2 =  f"cat /tmp/cut | cut -d 'E' -f 3 | cut -d \"'\" -f 3 | sed -n {j+1}p"
			commande2 =  f"cat /tmp/cut | cut -d 'S' -f 2 | cut -d ',' -f 2 | cut -d \"'\" -f 4 | sed -n {j+1}p"
			start = subprocess.check_output(commande1, shell=True).decode("utf-8")
			end = subprocess.check_output(commande2, shell=True).decode("utf-8")
			result = function(start, end, version)
			if plat and result :
				ID = x["CVE_Items"][k]["cve"]["CVE_data_meta"]["ID"]
				discription = x["CVE_Items"][k]["cve"]["description"]["description_data"][0]["value"]
				score = x["CVE_Items"][k]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
				print("--------------------------------------------")
				print("vulnerability found")
				print("--------------------------------------------")
				print("detail")
				print("--------------------------------------------")
				print(f"id: {ID}")
				print(f"description: {discription}")
				print(f"score: {score}")
				print("--------------------------------------------")
				break
			else:
				print("not vulnirable")
				j += 1


	k +=1











#cat try3 | grep -o -P '.{0,65}versionStartIncluding.{0,40}' | cut -d "'" -f 9
#start = $(cat try3 | grep -o -P '.{0,65}versionStartIncluding.{0,40}' | cut -d "'" -f 5 | sed -n "{i}p")
#end = $(cat try3 | grep -o -P '.{0,65}versionStartIncluding.{0,40}' | cut -d "'" -f 9 | sed -n "{i}p")
#ver = cat try3 | grep ver












"""	try:
		print(team["CVE_Items"][i]["configurations"]["nodes"][0]["children"][0]["cpe_match"][0]["cpe23Uri"])
		try:
			print(team["CVE_Items"][i]["configurations"]["nodes"][0]["children"][0]["cpe_match"][0]["versionEndExcluding"])
		except:
			pass
		try:
			print(team["CVE_Items"][i]["configurations"]["nodes"][0]["children"][0]["cpe_match"][0]["versionStartExcluding"])
			i = i+1
			j = j + 1
		except:
			pass
			i = i+1
			j = j + 1
	except:
		try:
			print(team["CVE_Items"][i]["configurations"]["nodes"][0]["cpe_match"][0]["cpe23Uri"])
			i=i+1
		except:
			print("there's no data about this vuln")
			i = i+1

print(f)
print(j)"""