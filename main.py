import imp
from unicodedata import name
from flask import Flask, render_template,request,redirect,make_response,jsonify,flash
from secure_cookie.cookie import SecureCookie
from Services import IOCService
from Services import ThreatIOCService
from flask_caching import Cache


app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

#Caching Flask
config = {
    "DEBUG": True,          # some Flask specific configs
    "CACHE_TYPE": "SimpleCache",  # Flask-Caching related configs
    "CACHE_DEFAULT_TIMEOUT": 86400
}
app.config.from_mapping(config)
cache = Cache(app)

#Routes
@app.route('/',methods=["GET","POST"])
def home():
    if cache.get("iocs") == None:
        iocs = ThreatIOCService().get_iocs()
        cache.set("iocs",iocs)
    else:
        iocs = cache.get("iocs")
    
    if request.method == "POST":
        data = {}
        for ioc in iocs:
            if (not ioc.name in data and len(data)<5):
                data[ioc.name] = 1
            elif(ioc.name in data):
                data[ioc.name] = data[ioc.name]+1
        return jsonify(data=[s.toDict() for s in iocs], chartjs=data)

    return render_template('index.html',data=iocs)



@app.route('/analyze')
def analyze():
    return  render_template('analyze.html')

@app.route('/config')
def config():
    user_config = request.cookies.get('userConfig')

    if user_config == None:
        return  render_template('config.html',data={"user_config":""})
    
    return render_template('config.html',data={"user_config":SecureCookie.unserialize(user_config,"Admin123456789.")})


@app.route('/save-config',methods=['POST'])
def saveconfig():
    if request.method == 'POST':
        user_config = {
            "API_KEY":request.form['api_key_vt'],
            "API_KEY_ABUSEIP":request.form['api_key_abuseip']
        }     
        resp = make_response(redirect("/analyze"))
        x = SecureCookie(user_config,"Admin123456789.")
        resp.set_cookie('userConfig', x.serialize())
        return resp


@app.route('/search',methods=['POST'])
def search():
    iocs_textarea = request.form["note"]
    iocs = []
    user_config = request.cookies.get('userConfig')

    if user_config == None:
        flash('No se encuentran definidas las API KEY - Ir a la página de configuración', 'error')
        return  redirect('analyze')

    user_config = SecureCookie.unserialize(user_config,"Admin123456789.")

    ioc_lines = iocs_textarea.split("\n")
    for index,x in enumerate(ioc_lines):
        if len(x) > 2:
            ioc = IOCService(user_config).getIOC(x,index)
            iocs.append(ioc)
    return render_template('search.html',data=iocs)

    
