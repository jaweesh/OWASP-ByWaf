# required dictionary
options = {
   # <name>             <value>    <default value>   <required>  <description>
  'DBSTORE_ENGINE':     ('',       'sqlite',         'Yes',       'Database engine to use (PostgreSQL, Sqlite, etc.)'),
  'DBSTORE_FILENAME':   ('',       ':memory:',       'Yes',       'Filename of the database store file'),
  'DEFAULT_TIMEOUT':    ('',       '2',              'No',        'Default timeouts on queries')
  }


"initializing testDB plugin"
from itertools import count
import time

app = None


# ------------
# Plugin commands


def do_produce_hosts(*_):
    """example: add 100 host entries to the database"""
    # create hosts
    try:
        for n in xrange(0, 256):
            ipstring = '192.168.0.%d' % n
            app.print_line("add %r %r" % (ipstring, 'my.own.website'))
            app.db.Host.add(app.db.get_session(), hostip=ipstring, hostname='my.own.website')
            time.sleep(5)
    except Exception, e: 
        app.print_line('do_produce_hosts():  Exception: {!r}'.format(e))


def do_consume_hosts(*_):
    """hang around and print host entries as they arrive"""
    try:
        for item in app.db.Host.get(app.db.get_session(), block=True, timeout=6):
            app.print_line('consume_hosts():  consumed host %r %r' % (item.hostip, item.hostname))
    except Exception, e:
        print('consume_hosts():  Exception: {}'.format(e))


def do_count_hosts(*_):
    """print a count of hosts in the database"""
    
    session = app.db.get_session()
    app.print_line('{} hosts in the database'.format(app.db.Host.count(session)))
            
