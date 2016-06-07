__author__ = 'oberon'
from time import sleep

from vitruvius.Backend import BackendBase

class Backend(BackendBase):
    def runner(self):

        delay = int(self.data['delay'])
        print("Waiting {s} seconds...".format(s=delay))
        sleep(delay)

        print("Ending Runner {0}".format(__name__))
