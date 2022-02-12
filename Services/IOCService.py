import re
from Models import Ioc
import requests
from Helpers.hash import detect_hash
from Helpers.ip import transform_country_code

class IOCService:
    def __init__(self,user_config):
        self.headers = {"vtotal":{'x-apikey' : user_config['API_KEY']},
        "abuseip":{'Accept': 'application/json','Key': user_config['API_KEY_ABUSEIP']}}
        self.regex_rules = {'domain':r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$','ip':r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}','hash':''}

    def abuseIP(self,ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': ip,'maxAgeInDays': '90'}
        response = requests.get(url,headers=self.headers['abuseip'],params=querystring)
        if re.search(self.regex_rules['ip'],ip) and len(response.json()['data']) > 0:
            data = response.json()['data']
            abuse_ip  = {"total_reports":str(data['totalReports']), "country":transform_country_code(data["countryCode"]),"isp":data["isp"]}
            return abuse_ip
        return "NA"

    def ip(self,data_all,ioc):
        data  = (data_all['attributes'])
        ioc.type = data_all['type']
        
        if('last_analysis_stats' in data):
            analysis = data['last_analysis_stats']
            total_detected = analysis['harmless'] + analysis['malicious'] + analysis['suspicious'] + analysis['undetected']
            ioc.reputation = "{0} / {1}".format(analysis['malicious'],total_detected)
        
        #Call Api for abuse IP
        abuse_ip = self.abuseIP(ioc.value)
        ioc.detection = 'abuseip: '+abuse_ip.get("total_reports")+' reports'
        ioc.isp = abuse_ip.get("isp")
        ioc.country = abuse_ip.get("country")

    def domain(self,data_all,ioc):
        data  = (data_all['attributes'])
        ioc.type = data_all['type']
        
        if('last_analysis_stats' in data):
            analysis = data['last_analysis_stats']
            total_detected = analysis['harmless'] + analysis['malicious'] + analysis['suspicious'] + analysis['undetected']
            ioc.reputation = "{0} / {1}".format(analysis['malicious'],total_detected)
        
    def hash(self,data_all,ioc):
        data  = (data_all['attributes'])
        if 'last_analysis_stats' in data:
            analysis = data['last_analysis_stats']
            total_detected = analysis['harmless'] + analysis['malicious'] + analysis['suspicious'] + analysis['undetected']
            ioc.reputation = "{0}/{1}".format(analysis['malicious'],total_detected)
        if('names' in data and len(data['names'])>0):
            name = data['names']
            if isinstance(name[0],str):
                ioc.name = name[0].strip()
        else:
            ioc.name = 'no identificado'
        detection_epp_env = "Symantec,BitDefender,Paloalto"
        array_detection = str.split(detection_epp_env,",")
        for detection_epp in array_detection:
            if len(detection_epp) > 2:
                if(detection_epp.strip() in data['last_analysis_results']):
                    epp_detect = data['last_analysis_results'][detection_epp]['category']
                    ioc.detection += detection_epp+': '+ epp_detect + ', '
                else:
                    ioc.detection += detection_epp+': '+ 'no detectado, ' 

    def getIOC(self,x,index):
        url = "https://www.virustotal.com/api/v3/search?query="+x.strip()
        response = requests.get(url, headers=self.headers['vtotal'])
        ioc = Ioc(str(index),x.strip())
        if re.search(self.regex_rules['domain'],x.lower()):
            if len(response.json()['data']) > 0:
                data_all = response.json()['data'][0]
                self.domain(data_all,ioc)
        elif re.search(self.regex_rules['ip'],x.lower()): 
            if len(response.json()['data']) > 0:
                data_all = response.json()['data'][0]
                self.ip(data_all,ioc)
        else:
            ioc.type = "Hash"+": "+detect_hash(ioc.value)
            if len(response.json()['data']) > 0:
                data_all = response.json()['data'][0]
                self.hash(data_all,ioc)
                
        return ioc