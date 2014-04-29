import socket
import shlex

app = None

options = {}


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
    app.print_line("Scanning port %d" % port)
    app.print_line('')
    for a in (xrange(0, 255) if ps[0] == 'x' else (int(ps[0]),)):
        for b in (xrange(0, 255) if ps[1] == 'x' else (int(ps[1]),)):
            for c in (xrange(0, 255) if ps[2] == 'x' else (int(ps[2]),)):
                for d in (xrange(0, 255) if ps[3] == 'x' else (int(ps[3]),)):
                    ipaddr = '%d.%d.%d.%d' % (a, b, c, d)
                    app.print_line("%s" % ipaddr)
                    s = None
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect((ipaddr, port))
                        app.print_line("Successful connection")
                        app.db.Host.add(app.db.get_session(), hostip=ipaddr, hostname='')
                    except IOError, ex:
                        app.print_line("Connection Error: %r" % str(ex))
                    finally:
                        if s:
                            try:
                                s.shutdown(socket.SHUT_WR)
                            except IOError:
                                pass
                            finally:
                                s.close()
                    app.print_line('')
