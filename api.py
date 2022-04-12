import requests, json
from datetime import date

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


url = "https://services.nvd.nist.gov/rest/json/cves/1.0/?modStartDate=2021-01-01T13:00:00:000%20UTC%2B01:00&modEndDate=2021-03-31T13:36:00:000%20UTC%2B01:00&keyword=docker"
r = requests.get(url)
for cve in json.loads(r.text)["result"]["CVE_Items"]:
	print(cve["cve"])


"""
for i in mounths:
	print(i[0])


r = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=docker")
print(r.text)"""
