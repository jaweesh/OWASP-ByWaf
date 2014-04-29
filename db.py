# set when plugin will be loaded
app = None


options = {}


def do_showdb(args):
    args = args.split()
    if not args:
        args = 'host', 'port'
    for dt in sorted(set(args)):
        dt = dt.lower()
        if dt == 'host':
            title = 'Host'
            tab = app.db.Host
            def printer(data):
                app.print_line("IP=%r Host=%r" % (data.hostip, data.hostname))
        elif dt == 'port':
            title = 'Port'
            tab = app.db.Port
            def printer(data):
                app.print_line("Protocol=%r | Port=%d | Service=%r | State=%r |"
                               " Status=%r | Hostid=%r" % (data.protocol,
                                                             data.port_number,
                                                             data.service_name,
                                                             data.state,
                                                             data.status,
                                                             data.hostid))
        else:
            app.print_line("tab %r unknown" % dt)
            continue
        try:
            app.print_line("Table: %r" % title)
            itemno = -1
            for itemno, item in enumerate(tab.get(app.db.get_session(), block=0)):
                printer(item)
            app.print_line('')
            app.print_line("%d rows" % (itemno + 1))
            app.print_line('-' * 40)
        except Exception as e:
            app.print_line('do_showdb(): Exception: %r' % str(e))
            raise


def do_puthost(args):
    args = args.split()
    if len(args) < 2:
        app.print_line("too few arguments")
        return -1
    # XXX check host ip
    ipstring = args[0].strip()
    hostname = args[1].strip()
    try:
        app.db.Host.add(app.db.get_session(), hostip=ipstring, hostname=hostname)
    except Exception as e:
        app.print_line('do_puthost(): Exception: %r' % str(e))
    