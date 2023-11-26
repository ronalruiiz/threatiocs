from flask import Flask, render_template,request,redirect,make_response,jsonify,Response
from secure_cookie.cookie import SecureCookie
from services import IOCService,ThreatIOCService,HeaderService
from flask_caching import Cache
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import os
import dns.resolver
from helpers.contex_processors import register_context_processors
from helpers.ip import obtener_ip, sanatize_ioc
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import base64


load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
register_context_processors(app)

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
    
    count_hashes = 0
    count_urls = 0
    count_domains = 0
    count_ips = 0

    if request.method == "POST":
        malwares = {}
        countries = {}
        for ioc in iocs:

            if ioc.type == "domain":
                count_domains+=1
            if ioc.type == "url":
                count_urls+=1
            if ioc.type.find("ip"):
                count_ips+=1
            if ioc.type.find("hash"):
                count_hashes+=1

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



        return jsonify(data=[s.to_dict() for s in iocs], chartjs={"malwares":malwares,"countries":countries}, report={"domains":count_domains,"urls":count_urls,"ips":count_ips,"hashes":count_hashes})

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
                ioc = IOCService(user_config).get_ioc(sanatize_ioc(x),index,epp)
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

@app.route('/lookup',methods=['POST','GET'])
def iplookup():
    if request.method == 'GET':
        return  render_template('lookup.html')
    if request.method == 'POST':
        dir_ip = sanatize_ioc(request.form["dir_ip"])
        url = 'http://ip-api.com/json/'+dir_ip.strip()+'?fields=message,continent,country,countryCode,regionName,city,lat,lon,timezone,currency,isp,org,asname,hosting'
        response = requests.get(url)
        response_spur = requests.get("https://spur.us/context/"+dir_ip)
        soup = BeautifulSoup(response_spur.text, 'lxml')
        h2_tag = soup.find('h2', class_='mb-3 text-left')
        vpn = h2_tag.find('span')
        result_vpn = "None"
        
        if response == None:
            return render_template('lookup.html', value={"value":""})
        if vpn != None:
            vpn = vpn.get_text(strip=True)
            result_vpn = vpn
        
        return render_template('lookup.html', value={"ipinfo":response.json(),"ip":obtener_ip(dir_ip),"vpn":result_vpn,"query":dir_ip})

#DNS Records
@app.route('/email/security-records',methods=['POST','GET'])
def security_records():

    if request.method == 'GET':
        return  render_template('security_record.html')
    if request.method == 'POST':
        domain = request.form["domain"]
        record = request.form["record"]
        selector = request.form["selector"]
        data = None
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
                    data = dns_data
                    response = {"result":data,"selector":selector,"domain":domain}           
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
    

#Route for Viewer Page

def capture_screenshot(url):
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')  # Agrega esta línea para evitar problemas con GPUs
    driver = webdriver.Chrome(options=chrome_options)

    driver.get(url)

    # Capturar la captura de pantalla como bytes en memoria
    screenshot_bytes = driver.get_screenshot_as_png()
    
    driver.quit()

    return screenshot_bytes

@app.route('/viewer-page',methods=['POST','GET'])
def viewerPage():
    if request.method == 'POST':
        url = request.form['url']
        try:
            screenshot_bytes = capture_screenshot(url)
            screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            return render_template('viewer_page.html', screenshot_base64=screenshot_base64,query=url)
        except Exception as e:
            return render_template('viewer_page.html', error=f"Error al obtener la imagen {e}")
        
    if request.method == 'GET':
        return  render_template('viewer_page.html')
