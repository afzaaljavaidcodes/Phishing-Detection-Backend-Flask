from flask import Flask, jsonify, request
from flask_cors import CORS
from urllib.parse import urlparse,urlencode
import ipaddress
import re
import pickle
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime

app = Flask(__name__)

model = pickle.load(open('../Phishing Detection Trained Model.pickle.dat', 'rb'))

cors = CORS(app)
cors = CORS(app, recources={r'/recommendation/*':{'origins': 'http://localhost:5173'}})
cors = CORS(app, recources={r'/diabetes-prediction/*':{'origins':'http://localhost:5173'}})
cors = CORS(app, resources={r'/heart-prediction/*':{'origins':'http://localhost:5173'}})
cors = CORS(app, recources={r'/recommendation':{'origins': 'http://localhost:5173'}})
cors = CORS(app, recources={r'/diabetes-prediction':{'origins':'http://localhost:5173'}})
cors = CORS(app, resources={r'/heart-prediction':{'origins':'http://localhost:5173'}})
CORS(app, resources={r"/*": {"origins": "*"}})
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 1
  except:
    ip = 0
  return ip

# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 1
  else:
    at = 0
  return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 0
  else:
    length = 1
  return length

# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in url:
    return 1
  else:
    return 0

#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 0            # legitimate

"""### **3.2. Domain Based Features:**

Many features can be extracted that come under this category. Out of them, below mentioned were considered for this project.

*   DNS Record
*   Website Traffic 
*   Age of Domain
*   End Period of Domain

Each of these features are explained and the coded below:
"""
"""#### **3.2.2. Web Traffic**

This feature measures the popularity of the website by determining the number of visitors and the number of pages they visit. However, since phishing websites live for a short period of time, they may not be recognized by the Alexa database (Alexa the Web Information Company., 1996). By reviewing our dataset, we find that in worst scenarios, legitimate websites ranked among the top 100,000. Furthermore, if the domain has no traffic or is not recognized by the Alexa database, it is classified as “Phishing”.

If the rank of the domain < 100000, the vlaue of this feature is 1 (phishing) else 0 (legitimate).
"""
def extract_domain(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme:
        domain = parsed_url.netloc
    elif url.startswith("www."):
        domain = url.split("www.")[-1]
    else:
        domain = url
    return domain

# 12.Web traffic (Web_Traffic)
def web_traffic(url):
    try:
        domain = extract_domain(url)
        app.logger.info("Domain : ",domain);
        google_url = f"https://www.semrush.com/website/{domain}/overview/"
        response = requests.get(google_url, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        b_texts = []
        divs_with_class = soup.find_all('div', class_='___SFlex_jt4ex_gg_ metrics-card__SCValueWrap-sc-3libca-3 kMVsZf')

        for div in divs_with_class:
            b_tags = div.find_all('b', class_='metrics-card__SCValue-sc-3libca-4 dwBSea ___SText_169rc_gg_ __fontWeight_169rc_gg_')
            for b_tag in b_tags:
                b_text = b_tag.text.strip()
                b_texts.append(b_text)

        VisitorsData=b_texts[0];
        if 'M' in VisitorsData:
            Visitors = VisitorsData.replace('M', '');
            data_float = float(Visitors)
            VisitorsData = int(data_float * 1000000)
        if 'B' in VisitorsData:
            Visitors = VisitorsData.replace('B', '');
            data_float = float(Visitors)
            VisitorsData = int(data_float * 100000000)
        app.logger.info("VisitorsData: ",VisitorsData)
        if VisitorsData>100000:
            return 1  # High traffic
        else:
            return 0  # Low traffic
    except Exception as e:
        return 0  # Error occurred

"""#### **3.2.3. Age of Domain**

This feature can be extracted from WHOIS database. Most phishing websites live for a short period of time. The minimum age of the legitimate domain is considered to be 12 months for this project. Age here is nothing but different between creation and expiration time.

If age of domain > 12 months, the vlaue of this feature is 1 (phishing) else 0 (legitimate).
"""

# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 0
  if ((expiration_date is None) or (creation_date is None)):
      return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 1
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age

"""#### **3.2.4. End Period of Domain**

This feature can be extracted from WHOIS database. For this feature, the remaining domain time is calculated by finding the different between expiration time & current time. The end period considered for the legitimate domain is 6 months or less  for this project. 

If end period of domain > 6 months, the vlaue of this feature is 1 (phishing) else 0 (legitimate).
"""

# 14.End time of domain: The difference between termination time and current time (Domain_End)
def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 1
  if (expiration_date is None):
      return 1
  elif (type(expiration_date) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end

"""## **3.3. HTML and JavaScript based Features**

Many features can be extracted that come under this category. Out of them, below mentioned were considered for this project.

*   IFrame Redirection
*   Status Bar Customization
*   Disabling Right Click
*   Website Forwarding

Each of these features are explained and the coded below:
"""

# importing required packages for this section
import requests

"""### **3.3.1. IFrame Redirection**

IFrame is an HTML tag used to display an additional webpage into one that is currently shown. Phishers can make use of the “iframe” tag and make it invisible i.e. without frame borders. In this regard, phishers make use of the “frameBorder” attribute which causes the browser to render a visual delineation. 

If the iframe is empty or repsonse is not found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""

# 15. IFrame Redirection (iFrame)
def iframe(response):
  if response == "":
      return 0
  else:
      if re.findall(r"[<iframe>|<frameBorder>]", response.text):
          return 1
      else:
          return 0

"""### **3.3.2. Status Bar Customization**

Phishers may use JavaScript to show a fake URL in the status bar to users. To extract this feature, we must dig-out the webpage source code, particularly the “onMouseOver” event, and check if it makes any changes on the status bar

If the response is empty or onmouseover is found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""

# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
  if response == "" :
    return 0
  else:
    if re.findall("<script>.+onmouseover.+</script>", response.text):
      return 1
    else:
      return 0

"""### **3.3.3. Disabling Right Click**

Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and check if the right click is disabled.

If the response is empty or onmouseover is not found then, the value assigned to this feature is 1 (phishing) or else 0 (legitimate).
"""

# 17.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
  if response == "":
    return 0
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1

"""### **3.3.4. Website Forwarding**
The fine line that distinguishes phishing websites from legitimate ones is how many times a website has been redirected. In our dataset, we find that legitimate websites have been redirected one time max. On the other hand, phishing websites containing this feature have been redirected at least 4 times.
"""

# 18.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
  if response == "":
    return 0
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1


def featureExtraction(url):
    features = []
    # Address bar based features (10)
    # features.append(getDomain(url))
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))
    #
    # Domain based features (4)
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))
    #
    # HTML & Javascript based features
    try:
        response = requests.get(url)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))
    return features

@app.route('/phishing_prediction', methods=['POST'])
def phishing():
    data = request.json
    features = featureExtraction(data['url']);
    # return features;
    # features=[[0,0,1,2,0,0,0,0,1,1,1,1,0,0,1,0]]
    #make prediction
    prediction = model.predict([features])
    return jsonify({'result': int(prediction),'features':features})

