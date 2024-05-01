import requests

cve_list_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
cve_id = "CVE-2019-1010218"
cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

def get_cve_list():

    vuln = []

    total_records = requests.get(cve_list_url).json()['totalResults']

    try:
        for i in range(0,12000,2000): #range(0,total_records,2000) would extract all the CVE's. Here I tested out the project with 12000 CVEs since it would take less time to extract.
            cve_list_response = requests.get(cve_list_url + f"?startIndex={i}").json() #returns a json-object with key - pairs
            cve_list_keys = ['resultsPerPage','startIndex','totalResults','format','version','timestamp','vulnerabilities'] #keys returned by the request
            vulnerabilities = cve_list_response['vulnerabilities'] #Contains information about all the CVE's is a list
            vulnerabilities_keys = ['cve'] #The key returned by vulnerabilities request
            vuln += vulnerabilities.copy()
    except Exception:
        pass

    return vuln.copy()

def get_cve_detail(cve_id):
    cve_specific_url = cve_url + cve_id
    cve_detail = requests.get(cve_specific_url).json()
    return cve_detail

def add_cve_details(cve_id,db,Details,CPEMATCH):
    try:
        response = get_cve_detail(cve_id)['vulnerabilities'][0]['cve']
        description = response['descriptions'][0]['value']
        cvssMetricV2 = response['metrics']['cvssMetricV2'][0]
        severity = cvssMetricV2['baseSeverity']
        baseScore = cvssMetricV2['cvssData']['baseScore']
        vectorString = cvssMetricV2['cvssData']['vectorString']
        accessVector = cvssMetricV2['cvssData']['accessVector']
        accessComplexity = cvssMetricV2['cvssData']['accessComplexity']
        authentication = cvssMetricV2['cvssData']['authentication']
        confidentialityImpact = cvssMetricV2['cvssData']['confidentialityImpact']
        integrityImpact = cvssMetricV2['cvssData']['integrityImpact']
        availabilityImpact = vectorString = cvssMetricV2['cvssData']['availabilityImpact']
        exploitabilityScore= cvssMetricV2['exploitabilityScore']
        impactScore = cvssMetricV2['impactScore']
        cpeMatch=response['configurations'][0]['nodes'][0]
        for cpe in cpeMatch['cpeMatch']:
            if cpe['vulnerable'] == True:
                cpe['vulnerable']="True"
            else:
                cpe['vulnerable']="False"
            cpe_dat = CPEMATCH(cve_id=cve_id,vulnerable=cpe['vulnerable'],criteria=cpe['criteria'],matchCriteriaId=cpe['matchCriteriaId'])
            db.session.add(cpe_dat)
            db.session.commit()
        data = Details(cve_id=cve_id,description=description,severity=severity,exploitable_score=exploitabilityScore,impact_score=impactScore,vectorString=vectorString,score=baseScore,confidentiality_impact=confidentialityImpact,integrity_impact=integrityImpact,availability_impact=availabilityImpact,authentication=authentication,access_vector=accessVector,access_complexity=accessComplexity)
            
        db.session.add(data)
        db.session.commit()
    except Exception as e:
        pass
