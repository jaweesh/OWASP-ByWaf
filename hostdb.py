#!/usr/bin/python

# Changes 20140303 Roey Katz
#  - changes:
#  - changed 'cls' to 'klass' in BufferedDatabaseObject.get_buffer() and .add()
#  - changed get_buffer() to get(), with mode 'block' = False.  Specifiying block=True causes get() to return a constantly-updated queue.
#  - re-arranged and refactored get()


# to install PostgreSQL:
#    
#   sudo apt-get install postgresql; sudo -u postgres createrole roey; sudo -u postgres createdb bywaf
#

# standard Python imports
from collections import namedtuple
from functools import partial
import contextlib
import time

# Unfortunately the two items below are not available in Python 2.7.  
# So I copied the iter_except wholesale.

# from itertools import iter_except 
# from collections import ChainMap

import multiprocessing as mp
from Queue import Empty


# SQLAlchemy imports
from sqlalchemy import Sequence, String, ForeignKey, Table, Column, Integer, create_engine, MetaData, CheckConstraint


# we already have a func
from sqlalchemy.sql.expression import func as sqlalchemy_func

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from sqlite3 import dbapi2 as sqlite

# RecordType imports
from recordtype import recordtype

# Quickly define a handy container for use with lists
OutputQueueElement = recordtype('OutputQueueElement', ['event_object', 'queue_object'])

# set up database for creation (metadata.create() is called at the end of this module)
#engine = create_engine('sqlite:///:memory:', echo=False, connect_args={'check_same_thread':False}, poolclass=StaticPool)

app = None


# required dictionary
# FIXME:  Implement these options
options = {
   # <name>             <value>    <default value>   <required>  <description>
  'DBSTORE_ENGINE':     ('',       'sqlite',         'Yes',       'Database engine to use (PostgreSQL, Sqlite, etc.)'),
  'DBSTORE_FILENAME':   ('',       ':memory:',       'Yes',       'Filename of the database store file'),
  'DEFAULT_TIMEOUT':    ('',       '2',              'No',        'Default timeouts on queries')
}


# itertools.iter_except was not in my Python version so I copied it herea
def iter_except(func, exception, first=None):
    """ Call a function repeatedly until an exception is raised.
            
    Converts a call-until-exception interface to an iterator interface.
    Like __builtin__.iter(func, sentinel) but uses an exception instead
    of a sentinel to end the loop.
    
    Examples:
        bsddbiter = iter_except(db.next, bsddb.error, db.first)
        heapiter = iter_except(functools.partial(heappop, h), IndexError)
        dictiter = iter_except(d.popitem, KeyError)
        dequeiter = iter_except(d.popleft, IndexError)
        queueiter = iter_except(q.get_nowait, Queue.Empty)
        setiter = iter_except(s.pop, KeyError)
        
        """
    try:
        if first is not None:
            yield first()
        while 1:
            yield func()
    except:
        pass


class HostDB(object):

    def __init__(self, path='bywaf.db'):
        # SQLA follows RFC-1738, and is of the form: protocol://username:password@host:port/database
        engine = create_engine("sqlite+pysqlite:///%s" % path, module=sqlite)
        self.Session = sessionmaker()
        self.Session.configure(bind=engine)

        # set up session that HostDB methods will use to communicate with the database
        metadata = MetaData(engine)

        # create a base for subclass definitions below
        Base = declarative_base(metadata=metadata)

        class BufferedDatabaseObject(object):
            """Mixin class for inheritence with Base; provides blocking get_buffer() and buffer-aware add() functionality"""

            @classmethod
            def get(klass, session, block=False, timeout=0):
                """retrieve table rows as SQLAlchemy's Declarative objects
                
                block - once the table's values have all been yielded,
                        caller caller waits on get().  This is useful in the
                following context:
                             
                            for table_element in table_class_instance.get(session, block=True, timeout=10):
                                  
                                # if timed out, then break out of the loop. 
                                    
                timeout - timeout that queue_object.get() sould wait before returning
                """
                offset = -1
                for offset, el in enumerate(session.query(klass).all()):
                    yield el
                if block:
                    while 1:
                        time.sleep(timeout)
                        query = session.query(klass)
                        query.offset(offset + 1)
                        elements = query.offset(offset + 1).all()
                        if elements:
                            _offset = -1
                            for _offset, el in enumerate(elements):
                                yield el
                            offset += _offset + 1
                        else:
                            break
                    

            @classmethod
            def add(klass, session, *args, **kwargs):
                """Add a new object given this type's parameters, and also updates all registered queues and wakes up waiting clients"""
                try:
                    instance = klass(*args, **kwargs)
                    session.add(instance)
                    session.commit()
                except Exception, e:
                   app.print_line("hostdb.add(): got exception: {!r};".format(e))
                   session.rollback()
                finally:
                    session.close()
                return instance

            @classmethod
            def count(klass, session, *args, **kwargs):
                """Return a count of items in the table"""
                return session.query(klass).count()

        class Port(Base, BufferedDatabaseObject):
            """table of Port information; links back to Hosts table"""
            __tablename__ = 'Port'
            id = Column(Integer, Sequence('user_id_seq'), primary_key=True)
            protocol = Column(String(50))
            port_number = Column(Integer, CheckConstraint('port_number>0 and port_number<65536'))
            service_name = Column(String(50))
            state = Column(String(50))  # open, closed, buffered, etc.
            status = Column(Integer) # scheduled, checking, wontcheck
            hostid = Column(Integer, ForeignKey('Host.hostip'))

        class Host(Base, BufferedDatabaseObject):
            """table of Host information"""
            __tablename__ = 'Host'
            hostip = Column(String(30), primary_key=True)  # host IP as a dot-separated series of digits
            hostname = Column(String(50)) # host name

        class WafType(Base, BufferedDatabaseObject):
            """Table of WAF types"""
            __tablename__ = 'WafType'
            id = Column(Integer, Sequence('user_id_seq'), primary_key=True)    
            vendor = Column(String(50)) # vendor's name (e.g., IBM)
            name = Column(String(50)) # WAF name
            version = Column(String(50)) # WAF version

        class WafItem(Base, BufferedDatabaseObject):
            """Table of WAFs identified on hosts; links back to Ports and WafTypes tables"""
            __tablename__ = 'WafItem'
            id = Column(Integer, Sequence('user_id_seq'), primary_key=True)    
            url = Column(String(50)) # URL containing the WAF
            confidence = Column(Integer) # probability that from 0 to 100 (100 means verified)
            portid = Column(Integer, ForeignKey('Port.id'))  # references a Port (which references a Host)
            waftypeid = Column(Integer, ForeignKey('WafType.id')) # references a WafType

        class WafBypassString(Base, BufferedDatabaseObject):
            """Table of strings used to bypass WAFs; links to WafItems table"""
            __tablename__ = 'WafBypassString'
            id = Column(Integer, Sequence('user_id_seq'), primary_key=True)    
            bypass_string = Column(String(50)) # the string (excluding the domain)
            status = Column(Integer) #  Signifies whether this string is being processed.  SCHEDULED / INFLIGHT / SUCCEEDED / FAILED 
            wafitemid = Column(Integer, ForeignKey('WafItem.id')) # references a WafItem
        self.Port = Port
        self.Host = Host
        # create tables  (this line must stay after the class definitions above)
        metadata.create_all()

    def get_session(self):
        """return a new connection to the database"""
        return self.Session()
