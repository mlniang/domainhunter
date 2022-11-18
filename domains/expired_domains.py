
from bs4 import BeautifulSoup
import getpass
import sys
import time
import traceback

from domains.isource import ISource

class ExpiredDomains(ISource):
    def __init__(self, username = None, password = None):
        super(ExpiredDomains, self).__init__('expired-domains')
        self.host = 'https://member.expireddomains.net'
        # self.query_url = 'https://www.expireddomains.net/domain-name-search'

        if username:
            self.conf['username'] = username
        elif not self.conf.get('username', None):
            raise Exception('[-] Error: ExpiredDomains.net requires a username! Set it in your config')
        
        if password:
            self.conf['password'] = password
        elif not self.conf.get('password', None):
            # We retrieve it from user
            password = getpass.getpass("expireddomains.net Password: ")
            self.conf['password'] = password

    def _getIndex(self, cells, index):
        if cells[index].find("a") == None:
            return cells[index].text.strip()
        
        return cells[index].find("a").text.strip()

    def login(self, proxies: dict = {}):
        data = {'login': self.conf['username'], 'password': self.conf['password'], 'redirect_to_url': '/begin'}
    
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        r = self.session.post(self.host + "/login/", headers=self.headers, data=data, proxies=proxies, verify=False, allow_redirects=False)
        cookies = self.session.cookies.get_dict()

        if "location" in r.headers:
            if "/login/" in r.headers["location"]:
                print("[!] Login failed")
                sys.exit()

        if "ExpiredDomainssessid" in cookies:
            print("[+] Login successful.  ExpiredDomainssessid: %s" % (cookies["ExpiredDomainssessid"]))
        else:
            print("[!] Login failed")
            sys.exit()

    def list_domains(self, **args):
        domain_list = []
        urls = []

        maxresults = args.get('maxresults', 100)
        m = 200
        if maxresults < m:
            m = maxresults

        proxies = args.get('proxies', {})

        keyword = args.get('keyword', '')
        keyword_start = args.get('keyword_start', '')
        keyword_end = args.get('keyword_end', '')
        alexa = args.get('alexa', '')
        for i in range (0,(maxresults),m):
            urls.append('{}/domains/combinedexpired/?fwhois=22&fadult=1&start={}&ftlds[]=2&ftlds[]=3&ftlds[]=4&flimit={}&fdomain={}&fdomainstart={}&fdomainend={}&falexa={}'
                .format(self.host,i,m,keyword,keyword_start,keyword_end,alexa))

        max_reached = False
        for url in urls:

            print("[*] {}".format(url))
            domainrequest = self.session.get(url, verify=False, proxies=proxies)
            #print("DEBUG: {0}".format(str(self.session.cookies.get_dict())))
            
            domains = domainrequest.text
    
            # Turn the HTML into a Beautiful Soup object
            soup = BeautifulSoup(domains, 'html.parser')

            try:
                table = soup.find_all("table", class_="base1")
                tbody = table[0].select("tbody tr")
                

                for row in tbody:
                    # Alternative way to extract domain name
                    # domain = row.find('td').find('a').text

                    cells = row.findAll("td")
                    
                    if len(cells) == 1:
                        max_reached = True
                        break # exit if max rows reached

                    if len(cells) >= 1:
                        c0 = self._getIndex(cells, 0).lower()   # domain
                        c1 = self._getIndex(cells, 3)   # bl
                        c2 = self._getIndex(cells, 4)   # domainpop
                        c3 = self._getIndex(cells, 5)   # birth
                        c4 = self._getIndex(cells, 7)   # Archive.org entries
                        c5 = self._getIndex(cells, 8)   # Alexa
                        c6 = self._getIndex(cells, 10)  # Dmoz.org
                        c7 = self._getIndex(cells, 12)  # status com
                        c8 = self._getIndex(cells, 13)  # status net
                        c9 = self._getIndex(cells, 14)  # status org
                        c10 = self._getIndex(cells, 17)  # status de
                        c11 = self._getIndex(cells, 11)  # TLDs
                        c12 = self._getIndex(cells, 19)  # RDT
                        c13 = ""                    # List
                        c14 = self._getIndex(cells, 22)  # Status
                        c15 = ""                    # links

                        # create available TLD list
                        available = ''
                        if c7 == "available":
                            available += ".com "

                        if c8 == "available":
                            available += ".net "

                        if c9 == "available":
                            available += ".org "

                        if c10 == "available":
                            available += ".de "
                        
                        # Only grab status for keyword searches since it doesn't exist otherwise
                        status = ""
                        if keyword:
                            status = c14

                        if keyword:
                            # Only add Expired, not Pending, Backorder, etc
                            # "expired" isn't returned any more, I changed it to "available"
                            if c14 == "available": # I'm not sure about this, seems like "expired" isn't an option anymore.  expireddomains.net might not support this any more.
                                # Append parsed domain data to list if it matches our criteria (.com|.net|.org and not a known malware domain)
                                if (c0.lower().endswith(".com") or c0.lower().endswith(".net") or c0.lower().endswith(".org")) and (c0 not in maldomainsList):
                                    domain_list.append([c0,c3,c4,available,status])
                            
                        # Non-keyword search table format is slightly different
                        else:
                            # Append original parsed domain data to list if it matches our criteria (.com|.net|.org and not a known malware domain)
                            if (c0.lower().endswith(".com") or c0.lower().endswith(".net") or c0.lower().endswith(".org")) and (c0 not in maldomainsList):
                                domain_list.append([c0,c3,c4,available,status]) 
                if max_reached:
                    print("[*] All records returned")
                    break

            except Exception as e: 
                print("[!] Error: ", e)
                traceback.print_exc()
                pass

            # Add additional sleep on requests to ExpiredDomains.net to avoid errors
            time.sleep(5)
        
        return domain_list