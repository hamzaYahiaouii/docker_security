import sys
import requests, json
from datetime import date
from pymongo import MongoClient
import os
import re
import subprocess
 
def function(start, end, ver):
	try:
	    try:
	        start = float(start)
	        start = f'{start}.0'
	    except:
	        pass

	    start = start.split(".", 1)
	    end = end.split(".", 1)
	    ver = ver.split(".", 1)

	    try:
	        start[1] = float(start[1])
	        end[1] = float(end[1])
	    except:
	        start = start[1].split(".", 1)
	        end = end[1].split(".", 1)
	        ver = ver[1].split(".", 1)

	    ver[1] = float(ver[1])
	    float(start[0]),float(end[0]),float(ver[0]),float(start[1]),float(end[1]),
	    float(ver[1])
	    
	    
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
	except:
		print("ERROR")
    
   

daemon_correction = " "
runc_correction = " "
swarm_correction = " "
compose_correction = " "
docker_correction = " "

fault = [0,0,0,0,0]

daemon = { "platform":"docker" , "version":sys.argv[1] }
runc = { "platform":"runc" , "version":sys.argv[2] }
containerd = { "platform":"containerd" , "version":sys.argv[3] }

table = [daemon,runc,containerd]


for test in table:

	print(test)
	print("------------------------------------------")
	print("------------------------------------------")
	print("------------------------------------------")
	platform = test["platform"]
	version = test["version"]
	mounths = [["01", "03"], ["04", "06"], ["07", "09"], ["10", "12"]]

	todays_date = date.today()
	years = [ int(todays_date.year) - i  for i in range(1,11) ]
	database = dict()



	for year in years:
		for mounth in mounths:
			year = str(year)
			start = mounth[0]
			end = mounth[1]
			print(f"{year}-{mounth}")
			url = f"https://services.nvd.nist.gov/rest/json/cves/1.0/?modStartDate={year}-{start}-01T13:00:00:000%20UTC%2B01:00&modEndDate={year}-{end}-31T13:36:00:000%20UTC%2B01:00&keyword=docker"
			req = requests.get(url)
			r = requests.get(url)
			x = json.loads(r.text)["result"]
			string = "versionStart"
			k = 0
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
						pass
				else:
					j = 0
					file = open("/tmp/lopo", "w")
					file.write(f"{str(f)}\n")
					file.close()
					os.system("cat /tmp/lopo | grep -o -P '.{0,70}versionStart.{0,78}' > /tmp/cut")
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
							print(f"ID: {ID}")
							print(f"description: {discription}")
							print(f"score: {score}")
							print("--------------------------------------------")
							break
						else:
							pass
							j += 1


				k +=1







if fault[0] == 1:
    print(daemon_correction)
elif fault[1] == 1 :
    print(runc_correction)
if fault[2] == 1 :
    print(swarm_correction)
elif fault[3] == 1 :
    print(compose_correction)
elif fault[4] == 1 :
    print(docker_correction)
else:
	print("[+] Done")
	print("[+] There is no vulnirability in this container")




#docker version | grep  Engine -A 1 | sed -n 2p | cut -d " " -f 13
#runc -v | grep runc | cut -d " " -f 3
#docker version | grep -P containerd -A 1 | sed -n 2p | cut -d " " -f 13
