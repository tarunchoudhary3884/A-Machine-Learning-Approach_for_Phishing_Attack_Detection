from googlesearch import search
from flask import Flask, render_template, request
import pickle
from urllib.parse import urlparse, urlencode
import ipaddress
import re
# importing required packages for this section
import re
from bs4 import BeautifulSoup
import numpy as np
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
# Create the Flask application
app = Flask(__name__)

# Load the trained model from a .pkl file
with open('rf.pkl', 'rb') as f:
    model = pickle.load(f)


# 1.Domain of the URL (Domain)
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# 2.Checks for IP address in URL (Have_IP)


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
    if 'https' in domain:
        return 1
    else:
        return 0


# listing shortening services
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
    match = re.search(shortening_services, url)
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

# 12.Web traffic (Web_Traffic)


def web_traffic(url):
    try:
        # Filling the whitespaces in the URL if any
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
            "REACH")['RANK']
        rank = int(rank)
    except:
        return 1
    if rank < 100000:
        return 1
    else:
        return 0

# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)


def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
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

# 14.End time of domain: The difference between termination time and current time (Domain_End)


def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
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

# 15. IFrame Redirection (iFrame)


def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1

# 16.Checks the effect of mouse over on status bar (Mouse_Over)


def mouseOver(response):
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0

# 17.Checks the status of the right click attribute (Right_Click)


def rightClick(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1

# 18.Checks the number of forwardings (Web_Forwards)


def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1


def google_index(url):
    site = search(url, 5)
    return 1 if site else 0


def count_dot(url):
    count_dot = url.count('.')
    return count_dot


def count_www(url):
    url.count('www')
    return url.count('www')


def count_per(url):
    return url.count('%')


def count_ques(url):
    return url.count('?')


def count_hyphen(url):
    return url.count('-')


def count_equal(url):
    return url.count('=')

# Function to extract features


def featureExtraction(url):
    print("**************************************************************************************************************************************************************************************************************************")
    features = []

    # Address bar based features (10)
    # features.append(getDomain(url))

    print("1")
    features.append(haveAtSign(url))
    # features.append(havingIP(url))
    print("2")
    features.append(getLength(url))
    print("3")
    features.append(getDepth(url))
    print("4")
    features.append(redirection(url))
    print("5")
    features.append(httpDomain(url))
    print("6")
    features.append(tinyURL(url))
    print("7")
    features.append(prefixSuffix(url))
    # ['Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 'https_Domain', 'TinyURL'
    # , 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame', '

    # Domain based features (4)
    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
    print("8")
    features.append(dns)
    print("9")
    features.append(web_traffic(url))
    print("10")
    features.append(1 if dns == 1 else domainAge(domain_name))
    print("11")
    features.append(1 if dns == 1 else domainEnd(domain_name))
    print("**************************************************************************************************************************************************************************************************************************")

    # HTML & Javascript based features (4)
    try:
        response = requests.get(url)
    except:
        response = ""
    print("12")
    features.append(iframe(response))
    # Mouse_Over', 'Right_Click', 'Web_Forwards', 'Google_Index', 'count_dot', 'count_www',
    # 'count_per', 'count_ques', 'count_hyphen', 'count_equal']
    print("13")
    features.append(mouseOver(response))
    print("14")
    features.append(rightClick(response))
    print("15")
    features.append(forwarding(response))
    print("16")
    features.append(google_index(url))
    print("17")
    features.append(count_dot(url))
    print("18")
    features.append(count_www(url))
    print("19")
    features.append(count_per(url))
    print("20")
    features.append(count_ques(url))
    print("21")
    features.append(count_hyphen(url))
    print("22")
    features.append(count_equal(url))

    print(features)

    return features

# Define a route to handle the form input


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the user's input from the form
        input_data = request.form['input_data']
        print(input_data)

        features = featureExtraction(input_data)

        # Pass the input data to the trained model
        output_data = model.predict([features])

        # Display the output data on the web page
        # if (output_data == 1):
        #     output_data = 'Phishing'
        # else:
        #     output_data = 'Legitimate'
        return render_template('index.html', output_data=output_data)
    else:
        return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
