__author__ = 'Monzavi'
__email__ = 'monzavi@protonmail.com'
__donation_BTC = 'bc1qplq8fs0cf8px5tqlmzjyxy9zknkdzs3ha65lls'

"""
This is a script for version detection of Webmin remote server interface.

CVE-2022-36446
    software/apt-lib.pl in Webmin before 1.997 lacks HTML escaping for a UI command.
"""


import requests
import sys
from bs4 import BeautifulSoup
import time




class Webmin:
    def __init__(self,webAddress):

        self.webAdderss = webAddress


    def check_redirect_url(self):

        response = requests.get(self.webAdderss).text
        if 'Document follows' in response:
            parsed_html = BeautifulSoup(response,'html.parser')
            return parsed_html.find('a')['href']
        else:
            return self.webAdderss

    def version_detection(self,url):

        response_headers = requests.get(url).headers
        if response_headers['Server']:
            return str(response_headers['Server']).split('/')[1]

    def check_vulnerability(self,version:float):

        if version == 1.999 or version >= 1.997:

            return False

        elif version < 1.997:

            return True


def line_printer():
    print("\n")
    line = "*" * 30
    for char in line:
        time.sleep(.02)
        sys.stdout.write(char)
        sys.stdout.flush()

    print("\n")



if __name__ == '__main__':

    print("""
***********************************************************************************
   _______    ________    ___   ____ ___  ___       _____ _____ __ __  __ __  _____
  / ____/ |  / / ____/   |__ \ / __ \__ \|__ \     |__  // ___// // / / // / / ___/
 / /    | | / / __/________/ // / / /_/ /__/ /_____ /_ </ __ \/ // /_/ // /_/ __ \ 
/ /___  | |/ / /__/_____/ __// /_/ / __// __/_____/__/ / /_/ /__  __/__  __/ /_/ / 
\____/  |___/_____/    /____/\____/____/____/    /____/\____/  /_/    /_/  \____/  
***********************************************************************************
[1]: Check CVE-2022-36446 for a url
[2]: Check CVE-2022-36446 for an IP * Coming Soon *
[3]: Exit


    """)
    command = input('Enter a number: ')
    if command == '1':
        webaddress = input('Enter url: ')
        obj = Webmin(webAddress=webaddress)
        address = obj.check_redirect_url()
        line_printer()
        print('Webmin-HTTP-Server-Address: ', address)
        line_printer()
        detected_version = obj.version_detection(address)
        print('Webmin-Version: ', detected_version)
        line_printer()
        if obj.check_vulnerability(float(detected_version)) == True:
            print('** Vulnerable **')
        else:
            print('** is not Vulnerable **')
    elif command == 2:
        pass
    elif command == 3:
        pass
    else:
        pass
