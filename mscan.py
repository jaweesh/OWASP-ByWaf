import os
import shlex
import signal
import socket
from datetime import datetime
import multiprocessing as multip
import errno

app = None

options = {}


def _scan(ipaddr, port):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ipaddr, port))
        app.print_line("%s | %s | %d | OPEN" % (datetime.now(), ipaddr, port))
        host = app.db.Host.add(app.db.get_session(), hostip=ipaddr, hostname='')
        app.db.Port.add(app.db.get_session(), protocol='TCP', port_number=port, status='open', hostid=ipaddr)
    except IOError, ex:
        if ex.errno != errno.EINTR:
            app.print_line("%s | %s | %d | ERROR | %r" % (datetime.now(), ipaddr, port, str(ex)))
            host = app.db.Host.add(app.db.get_session(), hostip=ipaddr, hostname='')
            app.db.Port.add(app.db.get_session(), protocol='TCP', port_number=port, status='str(ex)', hostid=ipaddr)
    finally:
        if s:
            try:
                s.shutdown(socket.SHUT_WR)
            except IOError:
                pass
            finally:
                s.close()





def do_scan(args):
    fields = shlex.split(args.strip().lower())
    if not fields:
        app.print_line("Error: ip address expected")
        return -1
    ps = fields[0].strip().lower().split('.')
    if len(ps) != 4 or not all(((p.isdigit() and 0 <= int(p) < 256) or p == 'x') for p in ps):
        app.print_line("Error: invalid IPv4 address %r" % fields[0])
        return -1
    if len(fields) > 1:
        port = fields[1]
        if not port.isdigit() and not int(port) < 0:
            app.print_line("Error: invalid port %r" % port)
        port = int(port)
    else:
        port = 80
    def init_work(*_):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    pool = multip.Pool(processes=5, initializer=init_work)
    jobs = []
    #
    try:
        for a in (xrange(0, 256) if ps[0] == 'x' else (int(ps[0]),)):
            for b in (xrange(0, 256) if ps[1] == 'x' else (int(ps[1]),)):
                for c in (xrange(0, 256) if ps[2] == 'x' else (int(ps[2]),)):
                    for d in (xrange(0, 256) if ps[3] == 'x' else (int(ps[3]),)):
                        ipaddr = '%d.%d.%d.%d' % (a, b, c, d)
                        j = pool.apply_async(_scan, (ipaddr, port))
                        jobs.append(j)
        for j in jobs:
            j.get()
    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
    else:
        print "Quitting normally"
        pool.close()
        pool.join()
        
