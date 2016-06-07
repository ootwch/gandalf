"""
Backend to execute a python code step
"""
__author__ = 'oberon'

import sys
import traceback


from vitruvius.Backend import BackendBase, Result


class Backend(BackendBase):
    def runner(self):
        success = False
        message = "Initial message for Python backend"
        default_script = "print('No script found')"

        script = self.data.get('script', default_script)
        try:

            script_globals = dict()
            script_locals = dict()
            script_locals['response']=""

            exec(script, script_globals, script_locals)
            # message = f.getvalue()
        except SyntaxError as err:
            error_class = err.__class__.__name__
            detail = err.args[0]
            line_number = err.lineno
            message = "Syntax Error - {err} on line {line}".format(err=detail, line=line_number)
            self.log.warning(str(err))
            self.log.warning(message)
        except Exception as err:
            error_class = err.__class__.__name__
            detail = err.args[0]
            cl, exc, tb = sys.exc_info()
            line_number = traceback.extract_tb(tb)[-1][1]
            message = "Exception - {err} on line {line}".format(err=detail, line=line_number)
            self.log.error(message)
            message = detail
        else:
            success = True
            message = script_locals.get('response', 'No response from Python Script')

        print("Ending Runner {0}".format(__name__))
        return Result(success=success, result_str=message)
