from aws.infra.pause import FUNCTIONS, pause, resume, status


class FakeLambda:
    def __init__(self):
        self.reserved = {}

    def put_function_concurrency(self, FunctionName, ReservedConcurrentExecutions):
        self.reserved[FunctionName] = ReservedConcurrentExecutions

    def delete_function_concurrency(self, FunctionName):
        self.reserved.pop(FunctionName, None)

    def get_function_concurrency(self, FunctionName):
        return {"ReservedConcurrentExecutions": self.reserved[FunctionName]} if FunctionName in self.reserved else {}


def test_pause_throttles_every_function_to_zero_and_resume_undoes_it():
    lam = FakeLambda()
    assert set(status(lam).values()) == {"running"}
    pause(lam)
    assert lam.reserved == {f: 0 for f in FUNCTIONS} and set(status(lam).values()) == {"paused"}
    resume(lam)
    assert lam.reserved == {} and set(status(lam).values()) == {"running"}


def test_a_nonzero_reservation_is_not_reported_as_paused():
    lam = FakeLambda()
    lam.reserved[FUNCTIONS[0]] = 5
    assert status(lam)[FUNCTIONS[0]] == "running"
