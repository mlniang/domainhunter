#!/usr/bin/env python3

## Title:       domainhunter.py
## Author:      @joevest and @andrewchiles
## Description: Checks expired domains, reputation/categorization, and Archive.org history to determine 
##              good candidates for phishing and C2 domain names

# If the expected response format from a provider changes, use the traceback module to get a full stack trace without removing try/catch blocks
#import traceback
#traceback.print_exc()

import time 
import random
import argparse
import json
import os
import sys
from urllib.parse import urlparse

from providers.bluecoat import Bluecoat
from providers.cisco_talos import CiscoTalos
from providers.cisco_umbrella import CiscoUmbrella
from providers.ibm_xforce import IBMXForce
from providers.mcafee_wg import McAfeeWG
from domains.expired_domains import ExpiredDomains

__version__ = "20221118"

## Functions

def doSleep(timing):
    """Add nmap like random sleep interval for multiple requests"""

    if timing == 0:
        time.sleep(random.randrange(90,120))
    elif timing == 1:
        time.sleep(random.randrange(60,90))
    elif timing == 2:
        time.sleep(random.randrange(30,60))
    elif timing == 3:
        time.sleep(random.randrange(10,20))
    elif timing == 4:
        time.sleep(random.randrange(5,10))
    # There's no elif timing == 5 here because we don't want to sleep for -t 5


def downloadMalwareDomains(malwaredomainsURL):
    """Downloads a current list of known malicious domains"""

    url = malwaredomainsURL
    response = s.get(url=url,headers=headers,verify=False,proxies=proxies)
    responseText = response.text
    if response.status_code == 200:
        return responseText
    else:
        print("[-] Error reaching:{}  Status: {}").format(url, response.status_code)

def checkDomain(domain, unwantedResults = []):
    """Executes various domain reputation checks included in the project"""

    result = [domain]
    print('[*] Fetching domain reputation for: {}'.format(domain))

    if domain in maldomainsList:
        print("[!] {}: Identified as known malware domain (malwaredomains.com)".format(domain))
      
    bluecoat = Bluecoat().check(domain, proxies)
    if bluecoat not in unwantedResults:
        print("[+] {}: {}".format(domain, bluecoat))
        result.append(bluecoat)
    else:
        result.append("****")
    
    ibmxforce = IBMXForce().check(domain, proxies)
    if not ibmxforce in unwantedResults:
        print("[+] {}: {}".format(domain, ibmxforce))
        result.append(ibmxforce)
    else:
        result.append("****")

    ciscotalos = CiscoTalos().check(domain, proxies)
    if not ciscotalos in unwantedResults:
        print("[+] {}: {}".format(domain, ciscotalos))
        result.append(ciscotalos)
    else:
        result.append("****")

    try:
        umbrella = CiscoUmbrella(umbrella_apikey).check(domain, proxies)
        if not umbrella in unwantedResults:
            print("[+] {}: {}".format(domain, umbrella))
            result.append(umbrella)
        else:
            result.append("****")
    except Exception as e:
        umbrella = '[-] Error retrieving Umbrella reputation! {0}'.format(e)

    mcafeewg = McAfeeWG().check(domain, proxies)
    if not mcafeewg in unwantedResults:
        print("[+] {}: {}".format(domain, mcafeewg))
        result.append(mcafeewg)
    else:
        result.append("****")


    print("")
    
    return result

def solveCaptcha(url,session):  
    """Downloads CAPTCHA image and saves to current directory for OCR with tesseract"""
    
    jpeg = 'captcha.jpg'
    
    try:
        response = session.get(url=url,headers=headers,verify=False, stream=True,proxies=proxies)
        if response.status_code == 200:
            with open(jpeg, 'wb') as f:
                response.raw.decode_content = True
                shutil.copyfileobj(response.raw, f)
        else:
            print('[-] Error downloading CAPTCHA file!')
            return False

        # Perform basic OCR without additional image enhancement
        text = pytesseract.image_to_string(Image.open(jpeg))
        text = text.replace(" ", "").rstrip()
        
        # Remove CAPTCHA file
        try:
            os.remove(jpeg)
        except OSError:
            pass

        return text

    except Exception as e:
        print("[-] Error solving CAPTCHA - {0}".format(e))
        
        return False

def drawTable(header,data):
    """Generates a text based table for printing to the console"""
    data.insert(0,header)
    t = Texttable(max_width=maxwidth)
    t.add_rows(data)
    t.header(header)
    
    return(t.draw())

## MAIN
if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description='Finds expired domains, domain categorization, and Archive.org history to determine good candidates for C2 and phishing domains',
        epilog = '''
Examples:
./domainhunter.py -k apples -c --ocr -t5
./domainhunter.py --check --ocr -t3
./domainhunter.py --single mydomain.com
./domainhunter.py --keyword tech --check --ocr --timing 5 --alexa
./domaihunter.py --filename inputlist.txt --ocr --timing 5''',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-a','--alexa', help='Filter results to Alexa listings', required=False, default=0, action='store_const', const=1)
    parser.add_argument('-k','--keyword', help='Keyword used to refine search results', required=False, default="", type=str, dest='keyword')
    parser.add_argument('-c','--check', help='Perform domain reputation checks', required=False, default=False, action='store_true', dest='check')
    parser.add_argument('-f','--filename', help='Specify input file of line delimited domain names to check', required=False, default=False, type=str, dest='filename')
    parser.add_argument('--ocr', help='Perform OCR on CAPTCHAs when challenged', required=False, default=False, action='store_true')
    parser.add_argument('-r','--maxresults', help='Number of results to return when querying latest expired/deleted domains', required=False, default=100, type=int, dest='maxresults')
    parser.add_argument('-s','--single', help='Performs detailed reputation checks against a single domain name/IP.', required=False, default=False, dest='single')
    parser.add_argument('-t','--timing', help='Modifies request timing to avoid CAPTCHAs. Slowest(0) = 90-120 seconds, Default(3) = 10-20 seconds, Fastest(5) = no delay', required=False, default=3, type=int, choices=range(0,6), dest='timing')
    parser.add_argument('-w','--maxwidth', help='Width of text table', required=False, default=400, type=int, dest='maxwidth')
    parser.add_argument('-V','--version', action='version',version='%(prog)s {version}'.format(version=__version__))
    parser.add_argument("-P", "--proxy", required=False, default=None, help="proxy. ex https://127.0.0.1:8080")
    parser.add_argument("-u", "--username", required=False, default=None, type=str, help="username for expireddomains.net")
    parser.add_argument("-p", "--password", required=False, default=None, type=str, help="password for expireddomains.net")
    parser.add_argument("-o", "--output", required=False, default=None, type=str, help="output file path")
    parser.add_argument('-ks','--keyword-start', help='Keyword starts with used to refine search results', required=False, default="", type=str, dest='keyword_start')
    parser.add_argument('-ke','--keyword-end', help='Keyword ends with used to refine search results', required=False, default="", type=str, dest='keyword_end')
    parser.add_argument('-um','--umbrella-apikey', help='API Key for umbrella (paid)', required=False, default="", type=str, dest='umbrella_apikey')
    parser.add_argument('-q','--quiet', help='Surpress initial ASCII art and header', required=False, default=False, action='store_true', dest='quiet')
    args = parser.parse_args()

    # Load dependent modules
    try:
        import requests
        from bs4 import BeautifulSoup
        from texttable import Texttable
        
    except Exception as e:
        print("Expired Domains Reputation Check")
        print("[-] Missing basic dependencies: {}".format(str(e)))
        print("[*] Install required dependencies by running `pip3 install -r requirements.txt`")
        quit(0)

    # Load OCR related modules if --ocr flag is set since these can be difficult to get working
    if args.ocr:
        try:
            import pytesseract
            from PIL import Image
            import shutil
        except Exception as e:
            print("Expired Domains Reputation Check")
            print("[-] Missing OCR dependencies: {}".format(str(e)))
            print("[*] Install required Python dependencies by running: pip3 install -r requirements.txt")
            print("[*] Ubuntu\Debian - Install tesseract by running: apt-get install tesseract-ocr python3-imaging")
            print("[*] macOS - Install tesseract with homebrew by running: brew install tesseract")
            quit(0)
    
## Variables
    username = args.username

    password = args.password

    proxy = args.proxy

    alexa = args.alexa

    keyword = args.keyword
    
    check = args.check

    filename = args.filename
    
    maxresults = args.maxresults
    
    single = args.single

    timing = args.timing

    maxwidth = args.maxwidth
    
    ocr = args.ocr

    output = args.output

    keyword_start = args.keyword_start

    keyword_end = args.keyword_end

    umbrella_apikey = args.umbrella_apikey

    malwaredomainsURL = 'https://gitlab.com/gerowen/old-malware-domains-ad-list/-/raw/master/malwaredomainslist.txt'

    timestamp = time.strftime("%Y%m%d_%H%M%S")

    useragent = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)'

    headers = {'User-Agent':useragent}

    proxies = {}

    requests.packages.urllib3.disable_warnings()
 
    # HTTP Session container, used to manage cookies, session tokens and other session information
    s = requests.Session()

    if(args.proxy != None):
        proxy_parts = urlparse(args.proxy)
        proxies["http"] = "http://%s" % (proxy_parts.netloc)
        proxies["https"] = "https://%s" % (proxy_parts.netloc)
    s.proxies = proxies
    title = '''
 ____   ___  __  __    _    ___ _   _   _   _ _   _ _   _ _____ _____ ____  
|  _ \ / _ \|  \/  |  / \  |_ _| \ | | | | | | | | | \ | |_   _| ____|  _ \ 
| | | | | | | |\/| | / _ \  | ||  \| | | |_| | | | |  \| | | | |  _| | |_) |
| |_| | |_| | |  | |/ ___ \ | || |\  | |  _  | |_| | |\  | | | | |___|  _ < 
|____/ \___/|_|  |_/_/   \_\___|_| \_| |_| |_|\___/|_| \_| |_| |_____|_| \_\ '''

    # Print header
    if not (args.quiet):
        print(title)
        print('''\nExpired Domains Reputation Checker
Authors: @joevest and @andrewchiles\n
DISCLAIMER: This is for educational purposes only!
It is designed to promote education and the improvement of computer/cyber security.  
The authors or employers are not liable for any illegal act or misuse performed by any user of this tool.
If you plan to use this content for illegal purpose, don't.  Have a nice day :)\n''')

    # Download known malware domains
    # print('[*] Downloading malware domain list from {}\n'.format(malwaredomainsURL))
    
    maldomains = downloadMalwareDomains(malwaredomainsURL)
    maldomainsList = maldomains.split("\n")

    # Retrieve reputation for a single choosen domain (Quick Mode)
    if single:
        checkDomain(single)
        exit(0)

    # Perform detailed domain reputation checks against input file, print table, and quit. This does not generate an HTML report
    if filename:
        # Initialize our list with an empty row for the header
        data = []
        try:
            with open(filename, 'r') as domainsList:
                for line in domainsList.read().splitlines():
                    data.append(checkDomain(line))
                    doSleep(timing)

                # Print results table
                header = ['Domain', 'BlueCoat', 'IBM X-Force', 'Cisco Talos', 'Umbrella', 'McAfee Web Gateway (Cloud)']
                print(drawTable(header,data))

        except KeyboardInterrupt:
            print('Caught keyboard interrupt. Exiting!')
            exit(0)
        except Exception as e:
            print('[-] Error: {}'.format(e))
            exit(1)
        exit(0)

    data = []

    # Generate list of URLs to query for expired/deleted domains
    try:
        expired_domains = ExpiredDomains(username, password)
        time.sleep(2)
        expired_domains.login(proxies=proxies)
    except Exception as e:
        print("{0}".format(e))
        exit(1)
    
    domain_list = expired_domains.list_domains(
        maxresults=maxresults,
        keyword=keyword,
        keyword_start = keyword_start,
        keyword_end = keyword_end,
        alexa = alexa,
        proxies=proxies
    )

    # Check for valid list results before continuing
    if len(domain_list) == 0:
        print("[-] No domain results found or none are currently available for purchase!")
        exit(0)
    else:
        domain_list_unique = []
        [domain_list_unique.append(item) for item in domain_list if item not in domain_list_unique]

        # Print number of domains to perform reputation checks against
        if check:
            print("\n[*] Performing reputation checks for {} domains".format(len(domain_list_unique)))
            print("")

        for domain_entry in domain_list_unique:
            domain = domain_entry[0]
            birthdate = domain_entry[1]
            archiveentries = domain_entry[2]
            availabletlds = domain_entry[3]
            status = domain_entry[4]
            bluecoat = '-'
            ibmxforce = '-'
            ciscotalos = '-'
            umbrella = '-'

            # Perform domain reputation checks
            if check:
                unwantedResults = ['Uncategorized','error','Not found.','Spam','Spam URLs','Pornography','badurl','Suspicious','Malicious Sources/Malnets','captcha','Phishing','Placeholders']
                
                results = checkDomain(domain, unwantedResults)
                # Sleep to avoid captchas
                doSleep(timing)

            # Append entry to new list with reputation if at least one service reports reputation
            if not (\
                (result[1] in ('Uncategorized','badurl','Suspicious','Malicious Sources/Malnets','captcha','Phishing','Placeholders','Spam','error')) \
                and (result[2] in ('Not found.','error')) \
                and (result[3] in ('Uncategorized','error')) \
                and (result[4] in ('Uncategorized','None')) \
                and (result[5] in ('Uncategorized','error'))):
                
                data.append([domain,birthdate,archiveentries,availabletlds,status,result[1],result[2],result[3],result[4],result[5]])

    # Sort domain list by column 2 (Birth Year)
    sortedDomains = sorted(data, key=lambda x: x[1], reverse=True) 

    if check:
        if len(sortedDomains) == 0:
            print("[-] No domains discovered with a desireable categorization!")
            exit(0)
        else:
            print("[*] {} of {} domains discovered with a potentially desireable categorization!".format(len(sortedDomains),len(domain_list)))

    # Build HTML Table
    html = ''
    htmlHeader = '<html><head><title>Expired Domain List</title></head>'
    htmlBody = '<body><p>The following available domains report was generated at {}</p>'.format(timestamp)
    htmlTableHeader = '''
                
                 <table border="1" align="center">
                    <th>Domain</th>
                    <th>Birth</th>
                    <th>Entries</th>
                    <th>TLDs Available</th>
                    <th>Status</th>
                    <th>BlueCoat</th>
                    <th>IBM X-Force</th>
                    <th>Cisco Talos</th>
                    <th>Umbrella</th>
                    <th>WatchGuard</th>
                    <th>Namecheap</th>
                    <th>Archive.org</th>
                 '''

    htmlTableBody = ''
    htmlTableFooter = '</table>'
    htmlFooter = '</body></html>'

    # Build HTML table contents
    for i in sortedDomains:
        htmlTableBody += '<tr>'
        htmlTableBody += '<td>{}</td>'.format(i[0]) # Domain
        htmlTableBody += '<td>{}</td>'.format(i[1]) # Birth
        htmlTableBody += '<td>{}</td>'.format(i[2]) # Entries
        htmlTableBody += '<td>{}</td>'.format(i[3]) # TLDs
        htmlTableBody += '<td>{}</td>'.format(i[4]) # Status

        htmlTableBody += '<td><a href="https://sitereview.bluecoat.com/" target="_blank">{}</a></td>'.format(i[5]) # Bluecoat
        htmlTableBody += '<td><a href="https://exchange.xforce.ibmcloud.com/url/{}" target="_blank">{}</a></td>'.format(i[0],i[6]) # IBM x-Force Categorization
        htmlTableBody += '<td><a href="https://www.talosintelligence.com/reputation_center/lookup?search={}" target="_blank">{}</a></td>'.format(i[0],i[7]) # Cisco Talos
        htmlTableBody += '<td>{}</td>'.format(i[8]) # Cisco Umbrella
        htmlTableBody += '<td><a href="https://sitelookup.mcafee.com/en/feedback/url?action=checksingle&url=http%3A%2F%2F{}&product=14-ts" target="_blank">{}</a></td>'.format(i[0],i[9]) # McAfee Web Gateway (Cloud)
        htmlTableBody += '<td><a href="http://www.borderware.com/domain_lookup.php?ip={}" target="_blank">WatchGuard</a></td>'.format(i[0]) # Borderware WatchGuard
        htmlTableBody += '<td><a href="https://www.namecheap.com/domains/registration/results.aspx?domain={}" target="_blank">Namecheap</a></td>'.format(i[0]) # Namecheap
        htmlTableBody += '<td><a href="http://web.archive.org/web/*/{}" target="_blank">Archive.org</a></td>'.format(i[0]) # Archive.org
        htmlTableBody += '</tr>'

    html = htmlHeader + htmlBody + htmlTableHeader + htmlTableBody + htmlTableFooter + htmlFooter

    logfilename = "{}_domainreport.html".format(timestamp)
    if output != None:
        logfilename = output

    log = open(logfilename,'w')
    log.write(html)
    log.close

    print("\n[*] Search complete")
    print("[*] Log written to {}\n".format(logfilename))
    
    # Print Text Table
    header = ['Domain', 'Birth', '#', 'TLDs', 'Status', 'BlueCoat', 'IBM', 'Cisco Talos', 'Umbrella']
    print(drawTable(header,sortedDomains))
