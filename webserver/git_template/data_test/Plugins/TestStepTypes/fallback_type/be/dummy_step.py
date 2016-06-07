import amphore.teststeptype


class DummyStepFactory(amphore.teststeptype.TestStepFactory):
    def test_step(self, name):
        return(DummyStepType(name, 'dummy_step.html'))


class DummyStepType(amphore.teststeptype.TestStepType):
    # def print_name(self):
    #     print("This is a dummy step with name " + self.config.test_step_name)
    #     super().print_name()

    def execute(self, callback=None):
        self.report.log_line("DUMMY", "SUCCESS", "Dummy step executed ok",None)
        return True




class DummyStepConfig(amphore.teststeptype.TestStepConfig):
    pass