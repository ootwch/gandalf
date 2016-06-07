from vitruvius.Backend import BackendBase, Result


class Backend(BackendBase):
    def runner(self, *args, **kwargs):
        wait_time=4
        self.log.debug("Starting Dummy Step - This won't do anything")
        self.log.debug("configuration: {0}".format(str(self.configuration)))
        return Result(True, result_str="Default Runner - all good!")
