#!/usr/bin/python2 -OOBRtt

# default
import atexit
from cmd import Cmd
from datetime import datetime
import imp
import itertools
import multiprocessing as multip
import os
import Queue
import re
from recordtype import recordtype
import shlex
import subprocess
import sys
import traceback
import types

# ext
import readline
from docopt import docopt

# db
import hostdb

# global constants
DEFAULT_MAX_CONCURRENT_JOBS = 10

# path to the root of the plugins directory
DEFAULT_PLUGIN_PATH = './'

# history file path
DEFAULT_HISTORY_FILENAME = './bywaf-history.txt'

INTRO = """
....____           _       __            ____
.../ __ )   __  __| |     / /  ____ _   / __/
../ __  |  / / / /| | /| / /  / __ `/  / /_  
./ /_/ /  / /_/ / | |/ |/ /  / /_/ /  / __/  
/_____/   \__, /  |__/|__/   \__,_/  /_/     
         /____/                             
"""

# create a handy named tuple to hold option values that are accessible by name
OptionRecord = recordtype('Option', ['current_value',  'default_value',
                                     'required', 'description'])


try:
    input = raw_input
except NameError:
    pass


def init_work(*_):
    # FIXME: Describe the use of this function in a doctstring
    import signal
    signal.signal(signal.SIGINT, signal.SIG_IGN)


NO_RESULT = object()


def do_shell(line):
    """Execute shell commands"""
    cmd = shlex.split(line)
    if not cmd:
        return None
    try:
        p = subprocess.Popen(cmd)
        t = p.communicate()
        return p.returncode
    except OSError as ex:
        return ex


BGD_TASKS = {'shell': do_shell}


app = None


class WAFterpreter(Cmd):

    def __init__(self, completekey='tab', stdin=sys.stdin, stdout=sys.stdout,
                 stderr=sys.stderr):
        Cmd.__init__(self, completekey, stdin, stdout)
        # base wafterpreter constants
        self.intro = INTRO
        self.base_prompt = "Bywaf"
        self.set_prompt()
        # no delegated input by default
        self.delegate_input_handler = None
        # currently loaded plugins, loaded & selected with he "use" command.
        # is a dictionary of { "plugin_name" : loaded_module_object }
        self.plugins = {}
        # dictionary of global variable names and values
        self.global_options = {}
        # jobs are spawned using this object's
        self.pool = multip.Pool(processes=DEFAULT_MAX_CONCURRENT_JOBS,
                                initializer=init_work)
        # running counter, increments with every job; used as Job ID
        self.job_counter = itertools.count(1)
        # job pool (list of runnign and completed Futures objects)      
        self.jobs = []
        # currently-selected plugin's name and object
        # (reference to a job in self.jobs)
        self.current_plugin = None
        self.current_plugin_name = ''
        # list of newly-finished backgrounded plugin command jobs
        self.finished_jobs = multip.Queue()
        self.results = {}
        # commands
        self.tasks = {}
        self.bgd = {}
        self.update_tasks(BGD_TASKS)
        # I/O
        self.stdout = stdout
        self.stdin = stdin
        self.stderr = stderr
        # db
        self.db = None
        hostdb.app = self
        #
        self.stop = 0

    def input(self, prompt=''):
        self.stdout.write(prompt)
        # XXX use self.stdin
        return input()

    def print_line(self, line):
        self.stdout.write(line)
        self.stdout.write('\n')

    def cmdloop(self):
        self.print_line(self.intro)
        while 1:
            try:
                Cmd.cmdloop(self, '')
                break
            except KeyboardInterrupt:
                self.print_line('')
        self.print_line("closing pool...")
        self.pool.close()
        # terminate all jobs
        running = 0
        for job in self.jobs:
            try:
                job.get(0)
            except multip.TimeoutError:
                running = 1
                break
        if running:
            while 1:
                yn = raw_input("Do you want wait %d running jobs? [Y/n]" % len(self.jobs)).lower()
                if yn == 'y':
                    wait = 1
                    break
                elif yn == 'n':
                    wait = 0
                    break
            if wait:
                self.print_line("waiting children...")
                self.pool.join()
                self.pool.terminate()
            else:
                self.print_line("terminate pool...")
                self.pool.terminate()
                self.pool.join()
        else:
            self.pool.terminate()

    def set_prompt(self, plugin=None):
        """Set the prompt with the given plugin name"""
        self.prompt = '%s%s> ' % (self.base_prompt,
                                  '' if plugin is None else '/%s' % plugin)

    def get_history_items(self):
        """Retrieve command history.
        Code adapted from pymotw.com/2/readline/"""
        return [readline.get_history_item(i)
                for i in xrange(1, readline.get_current_history_length() + 1)]

    def save_history(self, filename):
        """Try to write history to disk.
        It is the caller's responsibility to handle exceptions."""
        readline.write_history_file(filename)

    def load_history(self, filename):
        """Read history in, if it exists.
        It is the caller's responsibility to handle exceptions."""
        readline.read_history_file(filename)

    def clear_history(self):
        """Clear command history."""
        readline.clear_history()

    def update_tasks(self, bgd=None):
        for name in dir(self):
            if name.startswith('do_'):
                self.tasks[name[3:]] = getattr(self, name)
        if bgd is not None:
            self.tasks.update(bgd)
            self.bgd.update(bgd)

    # ----------- Overriden Methods -------------------------------------------
    #
    # The following methods from Cmd have been overriden to provide more
    # functionality 
    #
    # -------------------------------------------------------------------------
    def postcmd(self, stop, line):
        """Override Cmd.postcmd() to notify user if a backgrounded job has
        completed"""
        # if jobs just finished, then give the user notification
        # FIXME
        # Convert to this iterator form to get rid of the "while 1", 
        # for example below:
        # for job_id, val in iter_except(
        #                       partial(self.finished_jobs.get, False), Empty):
        while 1:
            try:
                job_id, val = self.finished_jobs.get(False)
                self.results[job_id] = val
            except Queue.Empty:
                break
            self.print_line("[%d] Done " %  job_id)
        # clear the finished jobs list
        return stop

    def emptyline(self):
        """Override Cmd.emptyline() so that it does not re-issue the last
        command by default"""
        return

    def postloop(self):
        """Override exit from command loop to say goodbye"""
        self.print_line('Goodbye')

    def get_names(self):
        return self.tasks.keys()

    def completenames(self, text, line, begidx, endidx, level=1):
        return tuple('%s ' % name
                     for name in self.get_names()
                     if name.startswith(text))

    # Utility method to autocomplete filenames.
    # Code adapted from: stackoverflow.com/questions/16826172
    # I added "level", which is the level of command at which text is being
    # completed.
    # level 1:  >command te<tab>   <-- text being completed here
    # level 2:  >command subcommand te<tab>  <-- text being completed here
    def filename_completer(self, text, line, begidx, endidx,
                           level=1, root_dir='./'):
        args= line.split()[level:]
        if not args:
            completions = os.listdir(root_dir)
        else:
            dir, part, base = args[-1].rpartition('/')
            if part == '':
                dir = './'
            elif dir == '':
                dir = '/'
            completions = []
            for f in os.listdir(dir):
                if f.startswith(base):
                    if os.path.isfile(os.path.join(dir, f)):
                        completions.append(f)
                    else:
                        completions.append(f+'/')
        return completions

    def onecmd(self, line):
        "Override Cmd.onecmd() to enable user to background a task"
        # call the delegation function first, if it has been defined
        if self.delegate_input_handler:
            self.delegate_input_handler(line)
            return
        # flag variable
        exec_in_background = False
        line = line.strip()
        # ignore comment lines
        if line.startswith('#'):
            return
        # if the user only specified a number, then show the results of that backgrounded task
        if line.isdigit():
            self.do_result(line)
            return
        # set the backgrounding flag if the line ends with &
        if line.endswith('&'):
            exec_in_background = True
            line = line[:-1]
            if not line:
                self.print_line("Error: syntax error, insert command before the '&'")
                return
        # extract command and its arguments from the line
        cmd, args, line = self.parseline(line)
        self.lastcmd = line
        # if the line is blank, return self.emptyline()
        if not cmd:
            if not args and not line:
                return self.emptyline()
            else:
                self.print_line("wrong cmd: %r" % line)
                return
        # quit on EOF
        elif cmd in ('EOF', 'quit', 'exit'):
            self.lastcmd = ''
            # 0 keeps WAFterpreter going, 1 quits it
            return 1
        # else, process the command
        else:
            func = self.tasks.get(cmd, None)
            if func is None:
                self.print_line("command %r not found" % cmd)
                return
            # list of commands for the currently-selected plugin
            # if user requested it, background the job
            # do not do this for internal commands                
            if exec_in_background: #and self.current_plugin and cmd in command_names:
                if cmd not in self.bgd:
                    self.print_line("error: command %r can't run in background" % cmd)
                    return
                func = self.bgd[cmd]
                job_id = self.job_counter.next()
                self.print_line("backgrounding job %r" % job_id)
                # background the job
                # TODO make globals dict
                job = self.pool.apply_async(func, (args,), callback=lambda v: self.finished_jobs.put((job_id, v)))
                job.job_id = job_id
                job.name = '%s/%s' % (self.current_plugin_name, cmd)
                job.command_line = line
                job.canceled = 0
                # add job to the list of running jobs
                # XXX not thread-safe
                self.jobs.append(job)
            # else, just run the job (returning 1 causes Bywaf to exit)
            else:
                func(args)

    def set_option(self, name, value):
        """Set an option's value.  Called by do_set()"""
        # defer first to the specific setter callback, if it exists
        try:
            setter_func = getattr(self.current_plugin, 'set_' + name)
            setter_func(value)
            
        # specific option setter callback doesn't exist,  so do a straight assignment
        except AttributeError as ex:
            # try setting the option with the default setter, if it exists
            try:
                self.current_plugin.set_default(name, value)

            # set_default() doesn't exist, fall back to original handler                            
            except AttributeError:
               try:
                    self.current_plugin.options[name].current_value = value
                    
               # that option name doesn't exist, so create a new record
               except KeyError:
                    self.current_plugin.options[name] = OptionRecord(current_value=value, default_value='', required=False, description='')

    def _load_module(self, filepath):
        """Physically load a module (called from do_import).
        Implementation adapted from http://stackoverflow.com/questions/301134/dynamic-module-import-in-python"""
        py_mod = None
        filepath = os.path.abspath(filepath)
        # extract module's name and extension from filepath
        mod_name,file_ext = os.path.splitext(filepath)
        dir_path, mod_name = os.path.split(mod_name)
        #
        fp = None
        try:
            fp, pathname, description = imp.find_module(mod_name, [dir_path])
            py_mod = imp.load_module(mod_name, fp, pathname, description)
        except ImportError, ex:
            self.print_line("Error: can't import module %r; %r" % (filepath, str(ex)))
            return None, None
        finally:
            # Since we may exit via an exception, close fp explicitly.
            if fp:
                fp.close()
        # verify that this module has the necessary Bywaf infrastructure
        if not hasattr(py_mod, "options"):
            self.print_line("Error: options dictionary not found in %r" % filepath)
            return None, None
        # convert the module's options dictionary to a dict of OptionRecords
        # so that we can access option value components by name rather than by index
        for opt_name in py_mod.options:
            # initialize the OptionRecord with the option's values
            py_mod.options[opt_name] = OptionRecord(*py_mod.options[opt_name])
            
        # return the loaded module
        return mod_name, py_mod

    # ----------- Command & Command Completion methods ---------------------- #
    def do_help(self, arg):
        # TODO
        self.print_line("""Bywaf. Help of command: %r""" % arg.strip())

    def do_show(self, args):
        """Display local vars for this plugin"""
        # if no plugin is currently selected
        if not self.current_plugin: 
           self.print_line('No plugin currently selected')
           return
        SHOW_COMMANDS = False
        SHOW_OPTIONS = False
        params = args.split()
        output_string = []
        # show all by default
        if params == []:
           params.append('all')
        if params[0] in ('options', 'all'):           
            if len(params) < 2:
                options_list = self.current_plugin.options.keys()
            else:
                options_list = params[1:]
            # construct the format string:  left-aligned, space-padded, minimum.maximum
            # name, value, defaultvalue, required, description
            format_string = '%-15s %-15s %-15s %-15s %-15s'
            # construct header string
            output_string.append('\n\n')
            output_string.append(format_string % ('Option', 'Value', 'Default Value', 'Required', 'Description'))
            output_string.append(format_string % ('-'*15, '-'*15, '-'*15, '-'*15, '-'*15))
            # construct table of values
            try:
                for name in options_list:
                    output_string.append(format_string % tuple(name, *self.current_plugin.options[name]))
            except KeyError:
                self.print_line("Error, no such option")
                return
        if params[0] in ('commands','all'):
               # show all options if no option name was given
               _command_list = self.current_plugin.commands
               if len(params) < 2:
                   commands_list = _command_list
               else:  # note: the if clause closes this comprehension to insecure lookups
                   commands_list = ['do_' + c for c in params[1:]]# if 'do_'+c in _command_list]
               # get the option names from the rest of the parameters.
               # construct the format string:  left-aligned, space-padded, minimum.maximum
               # name, value, defaultvalue, required, description                   
               # construct header 
               output_string.append('\n\n')
               output_string.append('%-20s %-20s' % ('Command', 'Description'))
               output_string.append('%-20s %-20s' % ('-' * 20, '-' * 20))
               try:
                   for c in commands_list:
                       cmd = getattr(self.current_plugin, c)
                       output_string.append('%-20s %-20s' % (cmd.__name__[3:], cmd.__doc__))
               except AttributeError:
                   self.print_line("Error, no such command")
                   return
               output_string.append('\n')    
        # display
        self.print_line('\n'.join(output_string))

    def do_history(self, params):
        """Load, save, display and clear command history"""
        cmd = params.split()
        # default to show history if no sub-actions specified       
        if not cmd:
            cmd.append('show')
        if cmd[0]=='load':
            try:
                fname = cmd[1]
                self.load_history(fname)
            except IndexError: # no filename specified
                self.print_line('filename not specified')
            except IOError as e: # error in loading file
                self.print_line('could not load file: {}'.format(e))
        elif cmd[0]=='save':
            try:
                fname = cmd[1]
                self.save_history(fname)
            except IndexError: # no filename specified
                self.print_line('filename not specified')
            except IOError as e: # error in saving file
                self.print_line('could not write file: {}'.format(e))
        elif cmd[0]=='show':
            self.print_line('\n'.join(self.get_history_items()))
        elif cmd[0]=='clear':
            self.clear_history()

    def do_set(self,arg):
        """set a plugin's local variable.  This command takes the form 'set VARNAME=VALUE VARNAME2=VALUE2 ... VARNAME=VALUEN.  Values can be enclosed in single- and double-quotes'."""
        # line taken from http://stackoverflow.com/questions/16710076/python-split-a-string-respect-and-preserve-quotes
        items = re.findall(r'(?:[^\s,"]|"(?:\\.|[^"])*")+', arg)
        if not self.current_plugin:
            self.print_line('no plugin selected; you must first select a plugin with the "use" command.')
            return
        if  len(items)==0:
            self.print_line('no option set')
            return
        for i in items:
            key, _, value = i.partition('=')
            if not value:
                self.print_line("Error: value for key %r not found" % key)
                break
            # remove double- and single-quotes from the split string, if it has any
            if (value.startswith('\'') and value.endswith('\'')) or (value.startswith('"') and value.endswith('"')):
                value = value[1:-1]
            # set the option
            try:
                self.print_line('%r => %r' % (key, value)) 
                self.set_option(key, value)
            except AttributeError:
                self.print_line('Unknown plugin option "{}"'.format(key))

    # completion function for the do_set command: return available option names
    def complete_set(self,text,line,begin_idx,end_idx):
        option_names = [opt+'=' for opt in self.current_plugin.options.keys() if opt.startswith(text)]
        return option_names

    def do_gset(self, args):
        """Set a global variable.  This command takes the form
        'gset VARNAME=VALUE VARNAME2=VALUE2 ... VARNAME=VALUEN.
        Values can be enclosed in single- and double-quotes'."""
        items = re.findall(r'(?:[^\s,"]|"(?:\\.|[^"])*")+', args)
        if len(items)==0:
           self.print_line('no gobal option name specified')
           return
        for i in items:
           key, _, value = i.partition('=')
           # remove double- and single-quotes from the split string, if it has any
           if (value.startswith('\'') and value.endswith('\'')) or (value.startswith('"') and value.endswith('"')):
               value = value[1:-1]
           # set the option
           try:
               self.print_line('[Global] %r => %r' % (key, value))
               self.global_options[key] = value
           except AttributeError:
               self.print_line('Unknown global option "{}"'.format(key))

    def complete_gset(self,text,line,begin_idx,end_idx):
        """Completion function for the do_gset command: return available global option names"""
        option_names = [opt+'=' for opt in self.global_options.keys() if opt.startswith(text)]
        return option_names 

    def do_gshow(self, args):
        """Show global variables."""
        # construct the format string:  function name, description
        format_string = '%-20s %s'
        if args:
            vars = args.split()
        else:
            vars = sorted(self.global_options.keys())
        # print the header
        self.print_line(format_string % ('Global Option', 'Value'))
        self.print_line(format_string % ('-' * 20, '-' * 20))
        not_found = []
        for key in vars:
            gopt = self.global_options.get(key, NO_RESULT)
            if gopt is NO_RESULT:
                not_found.append(key)
            else:
                self.print_line(format_string % (key, gopt))
        self.print_line('')
        for key in not_found:
            self.print_line("Error: global option %r not found" % key)

    def complete_gshow(self,text,line,begin_idx,end_idx):
        """Completion function for the do_gset command: return available global option names"""
        option_names = [opt+' ' for opt in self.global_options.keys() if opt.startswith(text)]
        return option_names

    def do_use(self, filepath):
        """Load a module given the module path"""
        filepath = filepath.strip()
        if not filepath:
            self.print_line("Insert the plugin's path")
            return
        plugin_path = self.global_options.get('PLUGIN_PATH', None)
        if plugin_path is None:
            self.print_line("Error: key PLUGIN_PATH not found")
            return
        if not os.path.exists(plugin_path):
            self.print_line("Error: %r not found" % plugin_path)
            return
        elif not os.path.isdir(plugin_path):
            self.print_line("Error: %r is not a directory" % plugin_path)
            return
        plugin_path = os.path.abspath(os.path.join(plugin_path, filepath))
        new_module_name = new_module = ''
        # TODO - HANDLE "ImportError" and "Exception: options dictionary not found"
        self.print_line("Loading path: %r" % plugin_path)
        new_module_name, new_module = self._load_module(plugin_path)
        if new_module_name is None or new_module is None:
            return 
        # if this plugin has already been loaded, notify user.
        # this will revert any changes they made to the options
        if self.current_plugin_name == new_module_name:
           self.print_line("Import: Overwriting already loaded module %r" % new_module_name)
        # give the new module access to other modules
        new_module.app = self
        globals()['new_module_name'] = new_module
        # remove currently selected plugin's functions from the Cmd command list
        if self.current_plugin:
            for command in self.current_plugin.commands:
                if hasattr(self, command):
                    delattr(self, command)
                if hasattr(self, 'help_'+command):
                    delattr(self, 'help_' + command[5:])
                if hasattr(self, 'complete_' + command):
                    delattr(self, 'complete_' + command[10:])
        # register with our list of modules (i.e., insert into our dictionary of modules)
        self.plugins[new_module_name] = new_module
        commands = [f for f in dir(new_module) if f.startswith('do_')]
        self.plugins[new_module_name].commands = commands
        # give plugin a link to its own path
        self.plugins[new_module_name].plugin_path = plugin_path
        # set current plugin
        # and change the prompt to reflect the plugin's name
        self.set_prompt(os.path.split(new_module_name)[1])
        self.current_plugin_name = new_module_name
        self.current_plugin = new_module
        # set module's options up by copying over the defaults
        # to the current values, if they have not yet been set
        for k in self.current_plugin.options:
            # option_record = OptionRecord(self.current_plugins.options[k])
            # extract option's values
            current_value, default_value, required, description = self.current_plugin.options[k]
            # set it to default value if current_value has not been set
            self.set_option(k, default_value)
        # add module's functions to the Cmd command list
        bgd = {}
        for command_name in new_module.commands:
            # register the command
            # it is a tuple of the form (function, string)
            command_func = getattr(new_module, command_name)
            setattr(self, command_name, command_func)
            # print command_name, type(command_func), isinstance(command_func, types.FunctionType)
            if isinstance(command_func, types.FunctionType):
                bgd[command_name[3:]] = command_func
            # try and register its optional help function, if one exists
            try:
                helpfunc = getattr(new_module, 'help_' + command_name[3:])
                setattr(self, helpfunc.__name__, helpfunc)
            except AttributeError:
                # help_ not found
                pass
            # try and register its optional completion function, if one exists
            try:
                completefunc = getattr(new_module, 'complete_' + command_name[3:])
                setattr(self, completefunc.__name__, completefunc)
            except AttributeError:
                # complete__ not found
                pass
        self.update_tasks(bgd)
        # call module's init_plugin(), if it exists
        try:
            initfunc = getattr(new_module, 'init_plugin')
            initfunc()
        except AttributeError: # init_plugin() not found
            pass
        self.pool.close()
        self.pool = multip.Pool(processes=DEFAULT_MAX_CONCURRENT_JOBS, initializer=init_work)

    def complete_use(self,text,line,begin_idx,end_idx):
        return self.filename_completer(text, line, begin_idx, end_idx,
                                  root_dir=self.global_options['PLUGIN_PATH'])

    def do_script(self, scriptfilename):
        """Load a script file"""
        try:
            with open(scriptfilename) as scriptfile:
                # loop over every input lines...
                for line in scriptfile:
                    # ...adding it to the command queue in turn.  
                    # This is a more elegant appraoch than
                    # calling self.onecmd())
                    self.cmdqueue.append(line)
        except IOError as e: 
            self.print_line('Could not load script file: {}'.format(e))

    def complete_script(self,text,line,begin_idx,end_idx):
        return self.filename_completer(text, line, begin_idx, end_idx,
                                root_dir=self.global_options['PLUGIN_PATH'])

    def complete_result(self,text,line,begin_idx,end_idx):
        """Completion function for the do_result command: return available
        global option names"""
        ids = ['%s ' % str(id)
               for id in self.results.keys()
               if str(id).startswith(text)]
        return ids

    def do_result(self, job_id):
        """Show the result of a job given its ID number"""
        if not job_id.isdigit():
            self.print_line("Error: invalid job ID")
            return
        job_id = int(job_id)
        val = self.results.get(job_id, NO_RESULT)
        if val is NO_RESULT:
            self.print_line("Error: no result for job %r" % job_id)
        else:
            self.print_line(repr(val))
        # verify that job ID is valid

    def do_jobs(self, *_):
        for job in self.jobs:
            self.print_line('%d %r [%r] = %r' % (job.job_id, job.command_line, job.name, self.results.get(job.job_id, '<Running>')))
        

__doc__ = """
Bywaf is a command-line tool for streamlining web application firewall
auditing.

Usage: bywaf [--input=INPUT] [--script=SCRIPT] [--out=OUT] [--plugin=PLUGIN] [--history=HISTORY] [--db=DB]

Options:
  --input=INPUT       read input from a file
  --script=SCRIPT     execute a script and stay in wafterpreter
  --out=OUT           redirect output to a file
  --plugin=PLUGIN     specify the root plugin directory [default: %s]
  --history=HISTORY   specify name of command history file [default: %s]
  --db=DB             specify the db's path [default: ./bywaf.db]
""" % (DEFAULT_PLUGIN_PATH, DEFAULT_HISTORY_FILENAME)
try:
    if __name__ == '__main__':
        opts = docopt(__doc__, sys.argv[1:], True)
        # check and parse opts
        opts['--input'] = open(os.path.abspath(opts['--input']), 'rb') \
                          if opts['--input'] else sys.stdin
        opts['--out'] = open(os.path.abspath(opts['--out']), 'wb') \
                        if opts['--out'] else sys.stdout

        if opts['--script'] is not None:
            if not opts['--script']:
                print("Error: invalid empty script's path")
                sys.exit(1)
            script = os.path.abspath(opts['--script'])
            if os.path.isfile(script):
                opts['--script'] = script
            else:
                print("Error: invalid --script path")
                sys.exit(1)

        plugin = os.path.abspath(opts['--plugin'])
        if os.path.isdir(plugin):
            opts['--plugin'] = os.path.abspath(opts['--plugin'])
        else:
            plugin = os.path.abspath(DEFAULT_PLUGIN_PATH)
            print("Error: invalid --plugin path, using default %r."% plugin)
            opts['--plugin'] = plugin
        # init interpreter
        app = wafterpreter = WAFterpreter(stdin=opts['--input'], stdout=opts['--out'])
        # init history
        history = os.path.abspath(opts['--history'])
        if os.path.exists(history):
            if os.path.isfile(history):
                opts['--history'] = history
                with open(history, 'a+b') as fh:
                    fh.write('# start %s\n' % (datetime.utcnow().isoformat(),))
                wafterpreter.load_history(history)
            else:
                history = os.path.abspath(DEFAULT_HISTORY_FILENAME)
                print("Error: invalid --history file, using default %r."
                      % history)
                with open(history, 'a+b') as fh:
                    fh.write('# start %s\n' % ( datetime.utcnow().isoformat(),))
                wafterpreter.load_history(history)
        else:
            with open(history, 'a+b') as fh:
                fh.write('# start %s\n' % (datetime.utcnow().isoformat(),))
            wafterpreter.load_history(history)
            opts['--history'] = history
        wafterpreter.global_options['HISTORY_FILENAME'] = history

        wafterpreter.global_options['PLUGIN_PATH'] = plugin
        plugin = os.environ.get('PLUGIN_PATH', opts['--plugin'])
        plugins = wafterpreter.global_options['PLUGIN_PATH'] = plugin
                                        
        if not os.path.exists(plugins):
            print("Error: puglins path not found {!r}".format(plugins))
        elif not os.path.isdir(plugins):
            print("Error: puglins path is not a directory %r" % (plugins,))

        db = hostdb.HostDB(os.path.abspath(opts['--db']))
        wafterpreter.db = db
        
        if opts['--script']:
            script = os.path.abspath(opts['--script'])
            if not os.path.exists(script):
                print("Error: script path not found %r" % script)
            elif not os.path.isfile(script):
                print("Error: script path is not a directory %r" % script)
            wafterpreter.do_script(script)
        else:
            def _atexit(*args):
                readline.write_history_file(history)
                with open(history, 'a+b') as fh:
                    fh.write('# end %s\n' % (datetime.utcnow().isoformat(),))
            atexit.register(_atexit)
            while 1:
                try:
                    wafterpreter.cmdloop()
                    break
                # handle an exception
                except KeyboardInterrupt:
                    print("Goodbye!")
                except Exception as e:
                    wafterpreter.print_line("\n"
                                    "error encountered, continue[Any-Key], "
                                    "show stack trace and continue[SC], show "
                                    "stack trace and quit[S] ")
                    # python2/3 compatibility check
                    try:
                        input = raw_input
                    except NameError:
                        pass
                    # ask user how they want to handle the exception
                    answer = input()
                    # show stack trace and quit
                    if answer == 'S' or answer == 's':
                        traceback.print_exc()
                        break
                    # show stack trace and continue
                    elif answer == 'SC' or answer == 'sc':
                        traceback.print_exc()
                    #present the error briefly            
                    else:
                        wafterpreter.print_line('%r\n' % str(e))
except KeyboardInterrupt:
    pass