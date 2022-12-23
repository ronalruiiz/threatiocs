from models import Ioc
import requests
from helpers.ip import transform_country_code

class ThreatIOCService:
    def threatfox(self):
        iocs = []
        url = "https://threatfox.abuse.ch/export/json/recent/"
        response = requests.get(url)
        response = response.json()
        for data in response:
            for ioc_json in response[data]:
                ioc = Ioc(data,ioc_json["ioc_value"],ioc_json["malware_printable"],ioc_json["ioc_type"],ioc_json["threat_type"],ioc_json["first_seen_utc"],country="Unkown")
                iocs.append(ioc)
        return (iocs)

    def get_iocs(self):
        iocs = self.threatfox() + self.feodotracker()
        return iocs

    def feodotracker(self):
        iocs = []
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        response = requests.get(url)
        response = response.json()
        for ioc_json in (response):
            ioc = Ioc(ioc_json["as_number"],ioc_json["ip_address"],ioc_json["malware"],"ip",ioc_json["as_name"],ioc_json["first_seen"],country=transform_country_code(ioc_json["country"]))
            iocs.append(ioc)
        return (iocs)