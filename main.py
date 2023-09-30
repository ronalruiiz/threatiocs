from flask import Flask, render_template,request,redirect,make_response,jsonify
from secure_cookie.cookie import SecureCookie
from services import IOCService,ThreatIOCService,HeaderService,VulnerabilityService
from flask_caching import Cache
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import os
import dns.resolver
from datetime import datetime,timedelta
from helpers.contex_processors import register_context_processors
from flask_cors import CORS


load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
register_context_processors(app)

# Configura CORS para permitir todas las solicitudes desde cualquier origen
CORS(app)

#Caching Flask
config = {
    "DEBUG": True,          # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 86400
}
app.config.from_mapping(config)
cache = Cache(app)

#Routes
#Route for Home
@app.route('/',methods=["GET","POST"])
def home():
    if cache.get("iocs") == None:
        iocs = ThreatIOCService().get_iocs()
        cache.set("iocs",iocs)
    else:
        iocs = cache.get("iocs")
    
    if request.method == "POST":
        malwares = {}
        countries = {}
        for ioc in iocs:
            if (not ioc.country in countries and ioc.country != "Unkown"):
                countries[ioc.country] = 1
            elif(ioc.country in countries):
                countries[ioc.country] = countries[ioc.country]+1

            if (not ioc.name in malwares):
                malwares[ioc.name] = 1
            elif(ioc.name in malwares):
                malwares[ioc.name] = malwares[ioc.name]+1

        malwares = dict(sorted(malwares.items(),key=lambda x: x[1],reverse=True))
        malwares = dict(list(malwares.items())[:5])

        countries = dict(sorted(countries.items(),key=lambda x: x[1],reverse=True))
        countries = dict(list(countries.items())[:5])

        return jsonify(data=[s.to_dict() for s in iocs], chartjs={"malwares":malwares,"countries":countries})

    return render_template('index.html')

#Routes for Analyze
@app.route('/analyze')
def analyze():
    return  render_template('analyze.html')

@app.route('/search',methods=["POST"])
def search():
    if request.method == "POST":
        iocs_textarea = request.form["note"]
        epp = request.form['epp']
        iocs = []
        user_config = request.cookies.get('userconfig')

        if user_config == None:
            return jsonify(data=[],status="error")

        user_config = SecureCookie.unserialize(user_config,os.getenv('SECRET_KEY'))
        ioc_lines = iocs_textarea.split("\n")
        for index,x in enumerate(ioc_lines):
            if len(x) > 2:
                ioc = IOCService(user_config).get_ioc(x,index,epp)
                iocs.append(ioc)
        return jsonify(data=[s.to_dict() for s in iocs],status="success")
    return redirect('analyze') 

#Route for Config
@app.route('/config')
def config():
    user_config = request.cookies.get('userconfig')

    if user_config == None:
        
        return  render_template('config.html',data={"user_config":""})
    
    return render_template('config.html',data={"user_config":SecureCookie.unserialize(user_config,os.getenv('SECRET_KEY'))})


@app.route('/save-config',methods=['POST'])
def saveconfig():
    if request.method == 'POST':
        user_config = {
            "API_KEY":request.form['api_key_vt'],
            "API_KEY_ABUSEIP":request.form['api_key_abuseip']
        }

        resp = make_response(redirect("/analyze"))
        x = SecureCookie(user_config,os.getenv('SECRET_KEY'))
        resp.set_cookie('userconfig', x.serialize())
        return resp

#Route for IP Info

@app.route('/iplookup',methods=['POST','GET'])
def iplookup():
    if request.method == 'GET':
        return  render_template('iplookup.html')
    if request.method == 'POST':
        dir_ip = request.form["dir_ip"]
        url = 'http://ip-api.com/json/'+dir_ip+'?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,currency,isp,org,as,asname,reverse,hosting,query'
        response = requests.get(url)
        response_spur = requests.get("https://spur.us/context/"+dir_ip)
        soup = BeautifulSoup(response_spur.text, 'lxml')
        vpn = soup.find("span",class_="bg-danger px-3")
        result_vpn = "None"
        
        if response == None:
            return render_template('iplookup.html', value={"value":""})
        if vpn != None:
            result_vpn = vpn.get_text().strip()
        
        return render_template('iplookup.html', value={"ipinfo":response.json(),"vpn":result_vpn})

#DNS Records

@app.route('/email/security-records',methods=['POST','GET'])
def security_records():

    if request.method == 'GET' and request.headers.get('X-Api-Request') == "true":

        domain = request.args.get('domain', "")
        record = request.args.get('record', "")
        selector = request.args.get('selector', "")

        print(domain,record,selector)

        response = {"data":""}
        try:
            if record == "SPF":
                test = dns.resolver.resolve(domain , 'TXT')
                query = 'spf1'

            if record == "DMARC":
                test = dns.resolver.resolve('_dmarc.' + domain , 'TXT')
                query = 'DMARC1'

            if record == "DKIM":
                test = dns.resolver.resolve(selector + '._domainkey.' + domain , 'TXT')
                query = 'DKIM1'
                
            for dns_data in test:
                if query in str(dns_data):
                    response = {"data":str(dns_data),"selector":selector,"query":domain}
        except:
            response = {"data":"[FAIL] record not found.","domain":domain}
        pass

        return jsonify(response)
    
    if request.method == 'GET':
        return  render_template('security_record.html')
    if request.method == 'POST':
        domain = request.form["domain"]
        record = request.form["record"]
        selector = request.form["selector"]

        response = {"result":""}
        try:
            if record == "SPF":
                test = dns.resolver.resolve(domain , 'TXT')
                query = 'spf1'

            if record == "DMARC":
                test = dns.resolver.resolve('_dmarc.' + domain , 'TXT')
                query = 'DMARC1'

            if record == "DKIM":
                test = dns.resolver.resolve(selector + '._domainkey.' + domain , 'TXT')
                query = 'DKIM1'
                
            for dns_data in test:
                if query in str(dns_data):
                    response = {"result":dns_data,"selector":selector,"domain":domain}
        except:
            response = {"result":"[FAIL] record not found.","domain":domain}
        pass

        return render_template('security_record.html', value=response,record=record)


#Route DNS Records

@app.route('/email/analyze-header',methods=['POST','GET'])
def analyze_header():
    if request.method == 'GET':
        return  render_template('header_analyzer.html')
    if request.method == 'POST':
        mail_data = request.form['headers'].strip()
        response = HeaderService().get_analyze(mail_data)

        print(response)
        return render_template('header_analyzer.html',data=response['data'], delayed=response['delayed'], summary=response['summary'],
            n=response['n'], security_headers=response['security_headers'])

#Route for Vulnerabilities

@app.route('/vulnerabilities',methods=['POST','GET'])
def vulnerabilities():
    if request.method == 'POST':
        print("")
        # date_end = datetime.now()
        # date_init = date_end - timedelta(days=30)
        # #date_init = request.form['date_init']
        # #date_end = request.form['date_end']

        # response = VulnerabilityService().get_vulnerabilities(date_init,date_end)
        # return jsonify(response)
    if request.method == 'GET':
        return  render_template('vulnerability.html')