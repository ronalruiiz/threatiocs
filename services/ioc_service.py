import re
from models import Ioc
import requests
from helpers.hash import detect_hash
from config.globals import regex_rules
from helpers.ip import transform_country_code

class IOCService:
    def __init__(self,user_config):
        self.headers = {"vtotal":{'x-apikey' : user_config['API_KEY']},
        "abuseip":{'Accept': 'application/json','Key': user_config['API_KEY_ABUSEIP']}}

    def abuse_ip(self,ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': ip,'maxAgeInDays': '90'}
        response = requests.get(url,headers=self.headers['abuseip'],params=querystring)
        if len(response.json()['data']) > 0:
            data = response.json()['data']
            abuse_ip  = {"total_reports":str(data['totalReports']), "country":transform_country_code(data["countryCode"]),"isp":data["isp"]}
            return abuse_ip
        return "NA"

    def ip(self,data,ioc):
        ioc.type = data['type']
        data  = data['attributes']
        
        if('last_analysis_stats' in data):
            analysis = data['last_analysis_stats']
            total_detected = analysis['harmless'] + analysis['malicious'] + analysis['suspicious'] + analysis['undetected']
            ioc.reputation = "{0} / {1}".format(analysis['malicious'],total_detected)
        
        #Call Api for abuse IP
        abuse_ip = self.abuse_ip(ioc.value)
        ioc.detection = 'abuseip: '+abuse_ip.get("total_reports")+' reports'
        ioc.isp = abuse_ip.get("isp")
        ioc.country = abuse_ip.get("country")

    def domain(self,data_all,ioc):
        data  = (data_all['attributes'])
        ioc.type = data_all['type']
        
        if('last_analysis_stats' in data):
            analysis = data['last_analysis_stats']
            sum_detected = analysis['harmless'] + analysis['malicious'] + analysis['suspicious'] + analysis['undetected']
            ioc.reputation = "{0} / {1}".format(analysis['malicious'],sum_detected)
        if('last_dns_records' in data):
            for record in data['last_dns_records']:
                if record['type'] == "A":
                    ioc.name =  record['value']
                    abuse_ip = self.abuse_ip(ioc.name)
                    ioc.detection = 'abuseip: '+abuse_ip.get("total_reports")+' reports'
                    ioc.isp = abuse_ip.get("isp")
                    ioc.country = abuse_ip.get("country")
        
    def hash(self,data,ioc,detection_epp_env):
        data  = data['attributes']
        
        if 'last_analysis_stats' in data:
            analysis = data['last_analysis_stats']
            total_detected = analysis['harmless'] + analysis['malicious'] + analysis['suspicious'] + analysis['undetected']
            ioc.reputation = "{0}/{1}".format(analysis['malicious'],total_detected)

        ioc.name = data['names'][0].strip() if('names' in data and len(data['names'])>0) else 'No identificado'
        ioc.other_value = "sha256: "+data['sha256']+" / md5: "+data['md5'] if ("sha256" in data) else ""

        array_detection = str.split(detection_epp_env,",")
        for detection_epp in array_detection:
            if len(detection_epp) > 2:
                if(detection_epp.strip() in data['last_analysis_results']):
                    epp_detect = data['last_analysis_results'][detection_epp]['category']
                    ioc.detection += detection_epp+': '+ epp_detect + ', '
                else:
                    ioc.detection += detection_epp+': '+ 'no detectado, ' 

    def get_ioc(self,input,index,epp):
        url = "https://www.virustotal.com/api/v3/search?query="+input.strip()
        response = requests.get(url, headers=self.headers['vtotal'])
        ioc = Ioc(str(index),input.strip())
        
        if len(response.json()['data']) > 0:
            data = response.json()['data'][0]
            if re.search(regex_rules['domain'],input.lower()) or re.search(regex_rules['url'],input.lower()):
                self.domain(data,ioc)
            elif re.search(regex_rules['ip'],input.lower()): 
                self.ip(data,ioc)
            else:
                ioc.type = "Hash"+": "+detect_hash(ioc.value)
                self.hash(data,ioc,epp)
                
        return ioc