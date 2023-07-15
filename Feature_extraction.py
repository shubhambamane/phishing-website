
import re
from urllib.parse import urlparse,urlencode
import urllib
from xml.dom import minidom
from tld import get_tld
import csv

def getSubDomain(url):
    try:
        res = get_tld(url, fail_silently=True, as_object=True)
        return res.subdomain
    except:
        return 0
    
def gettld(url):
    try:
        res = get_tld(url, fail_silently=True, as_object=True)
        return res.tld
    except:
        return 0

def getfld(url):
    try:
        res = get_tld(url, fail_silently=True, as_object=True)
        return res.fld
    except:
        return 0

def havingIP(url):
    match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
    if match:
        return 1          # phishing
    else:
        return -1         # legitimate   
    
def havinghttp(url):
    match = re.search("^http://", url)
    if match:   
        return 1                # Phishing
    else:
        return -1                # Legitimate
        
def long_url(url):
    l_url = len(url)
    if (l_url < 54):
        return -1           # legitimate
    elif l_url >= 54 and l_url <= 75:
        return  0          # suspicious
    else:
        return  1         # phishing
def atinurl(url):
    if re.findall("@", url):
        return 1               # Phishing
    else:
        return -1               # Legitimate

def slash(url):
    list=[x.start(0) for x in re.finditer('//', url)]
    if list[len(list)-1]>7:
        return 1                # Phishing
    else:
        return -1              # Legitimate
    
def hypen(url):             #prefix_suffix    
    if "-" in urlparse(url).netloc:
        return 1            # Phishing
    else:
        return -1           # Legitimate

def dots(url):        
    if (urlparse(url).netloc).count(".") < 3:
        return -1                    # Legitimate
    elif (urlparse(url).netloc).count(".") == 3:
        return 0                   # Suspicious
    else:
        return 1                    # phishing    
    
def phishterm(url):
    if (("secure" in url) or ("verify" in url) or ("logon" in url) or ("secure" in url) or ("websrc" in url) or ("ebaysapi" in url) or ("signin" in url) or ("banking" in url) or ("confirm" in url) or ("login" in url)):
        return 1           # phishing
    else:
        return -1           # legitimate  
    
def shorten(url):
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        return 1             # phishing
    else:
        return -1             # legitimate
   
def httpinpath(url):
    if ("https" in urlparse(url).path) or ("http" in urlparse(url).path) or ("https" in urlparse(url).netloc) or ("http" in urlparse(url).netloc):
        return 1           # phishing        
    else: 
        return -1           # legitimate    

def phishtld(url):
    try:
        res = get_tld(url, fail_silently=True, as_object=True)
        if ("tk" in res.tld) or ("cf" in res.tld) or ("ga" in res.tld) or ("ml" in res.tld) or ("cc" in res.tld) or ("gq" in res.tld) or ("br" in res.tld):
            return 1           # phishing        
        else: 
            return -1           # legitimate    
    except:
        return 0
 
def getresult(Phishing):
    if Phishing == 'Yes':
        return 1
    elif Phishing == 'No':
        return -1


def feature_extract(url_input):

        Feature={}
        tokens_words=re.split('\W+',url_input)       #Extract bag of words stings delimited by (.,/,?,,=,-,_)
        obj=urlparse(url_input)
        host=obj.netloc
        path=obj.path

        Feature['URL']=url_input                            #1
        Feature['Protocol']=urlparse(url_input).scheme      #2
        Feature['Domain']=urlparse(url_input).netloc        #3
        Feature['Subdomain']=getSubDomain(url_input)        #4
        Feature['TLD']=gettld(url_input)                    #5
        Feature['FLD']=getfld(url_input)                    #6
        Feature['Path']=urlparse(url_input).path            #7
        Feature['IP_in_URL']=havingIP(url_input)            #8
        Feature['http_in_URL']=havinghttp(url_input)        #9
        Feature['long_URL']=long_url(url_input)             #10
        Feature['AT_in_URL']=atinurl(url_input)             #11
        Feature['Slash']=slash(url_input)                   #12
        Feature['Hypen']=hypen(url_input)                   #13
        Feature['Dots']=dots(url_input)                     #14
        Feature['Phish_term']=phishterm(url_input)          #15
        Feature['Shorten']=shorten(url_input)               #16
        Feature['http_in_path']=httpinpath(url_input)       #17
        Feature['Phish_tld']=phishtld(url_input)            #18
        #Feature['Phishing']=getresult(Phishing)            #19
        # Feature['exe_in_url']=exe_in_url(url_input)
       
        return Feature