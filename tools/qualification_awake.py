"""Thread-scoped idle-sleep inhibition and independent Windows suspension check.

No power policy or display setting changes. Explicit lid/suspend remains possible
and invalidates qualification rather than silently extending an active-time clock.
"""
import ctypes
import os

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
SUSPEND_TOLERANCE_MS = 1000


class QualificationAwake:
    def __init__(self, *, windows=None, kernel=None):
        self.windows = os.name == 'nt' if windows is None else windows
        self.kernel = kernel
        self.previous = None
        self.started = None
        self.report = dict(platform='windows' if self.windows else 'other',
                           global_policy_changed=False, display_setting_changed=False,
                           idle_sleep_inhibited=False, released=False,
                           suspension_tolerance_ms=SUSPEND_TOLERANCE_MS,
                           max_observed_suspension_ms=0)

    def __enter__(self):
        if not self.windows:
            self.report.update(released=True, suspension_detection='not available on this platform')
            return self
        if self.kernel is None:
            self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.SetThreadExecutionState.argtypes = [ctypes.c_uint]
        self.kernel.SetThreadExecutionState.restype = ctypes.c_uint
        self.kernel.GetTickCount64.argtypes = []
        self.kernel.GetTickCount64.restype = ctypes.c_ulonglong
        self.kernel.QueryUnbiasedInterruptTime.argtypes = [ctypes.POINTER(ctypes.c_ulonglong)]
        self.kernel.QueryUnbiasedInterruptTime.restype = ctypes.c_int
        previous = self.kernel.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
        if not previous:
            raise RuntimeError('Windows qualification idle-sleep inhibition failed')
        self.previous = previous
        self.report['idle_sleep_inhibited'] = True
        self.report['suspension_detection'] = 'GetTickCount64 minus QueryUnbiasedInterruptTime'
        try:
            self.started = self._snapshot()
        except Exception:
            self._release()
            raise
        return self

    def _snapshot(self):
        # This tick source includes sleep, while unbiased interrupt time excludes
        # it. Wall-clock adjustments do not affect this comparison.
        tick = self.kernel.GetTickCount64()
        unbiased = ctypes.c_ulonglong()
        if not self.kernel.QueryUnbiasedInterruptTime(ctypes.byref(unbiased)):
            raise RuntimeError('Windows qualification suspension clock unavailable')
        return tick, unbiased.value // 10000

    def check(self):
        if not self.windows:
            return
        tick, awake = self._snapshot()
        if tick < self.started[0] or awake < self.started[1]:
            raise RuntimeError('Windows qualification clock moved backwards')
        gap = (tick - self.started[0]) - (awake - self.started[1])
        self.report['max_observed_suspension_ms'] = max(
            self.report['max_observed_suspension_ms'], gap)
        if gap > SUSPEND_TOLERANCE_MS:
            raise RuntimeError('Host suspension interrupted qualification')

    def _release(self):
        if self.previous is not None:
            previous, self.previous = self.previous, None
            if not self.kernel.SetThreadExecutionState(previous | ES_CONTINUOUS):
                raise RuntimeError('Windows qualification idle-sleep request release failed')
            self.report['released'] = True

    def __exit__(self, kind, value, traceback):
        try:
            self.check()
        finally:
            self._release()
