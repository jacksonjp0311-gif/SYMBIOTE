"""Simulated native clock/suspend failures; never alters global power settings."""
import ctypes
import unittest
from unittest import mock

from qualification_awake import ES_CONTINUOUS, ES_SYSTEM_REQUIRED, QualificationAwake


def kernel(ticks, awake):
    api = mock.Mock()
    api.SetThreadExecutionState.return_value = ES_CONTINUOUS
    api.GetTickCount64.side_effect = ticks
    values = iter(awake)

    def read(pointer):
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_ulonglong))[0] = next(values) * 10000
        return 1

    api.QueryUnbiasedInterruptTime.side_effect = read
    return api


class AwakeTests(unittest.TestCase):
    def test_owned_request_is_released_after_normal_and_failed_body(self):
        for failed in (False, True):
            api = kernel([100, 200], [80, 180])
            guard = QualificationAwake(windows=True, kernel=api)
            try:
                with guard:
                    if failed:
                        raise ValueError('controlled operation failure')
            except ValueError:
                self.assertTrue(failed)
            self.assertEqual(api.SetThreadExecutionState.call_args_list,
                             [mock.call(ES_CONTINUOUS | ES_SYSTEM_REQUIRED), mock.call(ES_CONTINUOUS)])
            self.assertTrue(guard.report['released'])
            self.assertFalse(guard.report['global_policy_changed'])

    def test_sleep_invalidates_run_even_if_operation_would_succeed(self):
        api = kernel([100, 30100], [80, 180])
        guard = QualificationAwake(windows=True, kernel=api)
        with self.assertRaisesRegex(RuntimeError, 'suspension interrupted'):
            with guard:
                pass
        self.assertEqual(guard.report['max_observed_suspension_ms'], 29900)
        self.assertTrue(guard.report['released'])

    def test_failed_acquisition_does_not_launch_or_release_an_unowned_request(self):
        api = kernel([], [])
        api.SetThreadExecutionState.return_value = 0
        with self.assertRaisesRegex(RuntimeError, 'inhibition failed'):
            with QualificationAwake(windows=True, kernel=api):
                self.fail('must not execute')
        api.GetTickCount64.assert_not_called()
        self.assertEqual(api.SetThreadExecutionState.call_count, 1)

    def test_clock_failure_and_backward_time_fail_closed_and_release(self):
        for api in (kernel([100, 90], [80, 180]), kernel([100, 200], [80, 70])):
            guard = QualificationAwake(windows=True, kernel=api)
            with self.assertRaisesRegex(RuntimeError, 'backwards'):
                with guard:
                    pass
            self.assertTrue(guard.report['released'])
        api = kernel([100], [])
        api.QueryUnbiasedInterruptTime.side_effect = None
        api.QueryUnbiasedInterruptTime.return_value = 0
        guard = QualificationAwake(windows=True, kernel=api)
        with self.assertRaisesRegex(RuntimeError, 'clock unavailable'):
            with guard:
                self.fail('must not execute')
        self.assertTrue(guard.report['released'])

    def test_other_platform_has_no_windows_calls_or_inhibition_claim(self):
        api = mock.Mock()
        with QualificationAwake(windows=False, kernel=api) as guard:
            guard.check()
        self.assertFalse(guard.report['idle_sleep_inhibited'])
        self.assertEqual(api.mock_calls, [])


if __name__ == '__main__':
    unittest.main()
