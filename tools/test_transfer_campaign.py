"""Manual binding counterexamples only; never open the prospective cohort."""
import json
import os
import contextlib
import io
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

import transfer_campaign as campaign


class TransferCampaignBindings(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows device-prefix aliases')
    def test_windows_aliases_compare_identically_and_cannot_escape_source_exclusion(self):
        plain = self.base/'not-created'
        extended = Path('\\\\?\\'+str(plain))
        self.assertEqual(campaign.canonical_path(plain), campaign.canonical_path(extended))
        with self.assertRaisesRegex(RuntimeError, 'unsupported absolute filesystem namespace'):
            campaign.canonical_path('\\\\.\\'+str(plain))
        for suffix in ('.', ' '):
            alias = campaign.ROOT.with_name(campaign.ROOT.name+suffix)/'state'/self.base.name
            with self.assertRaisesRegex(RuntimeError, 'trailing-dot or trailing-space'):
                campaign.canonical_path('\\\\?\\'+str(alias))
        inside = campaign.ROOT/'state'/self.base.name
        with self.assertRaisesRegex(RuntimeError, 'outside frozen source'):
            campaign.register(self.native, self.base/'state',
                              Path('\\\\?\\'+str(inside)), 'a'*40)
        with patch.object(campaign, 'ROOT', Path('\\\\?\\'+str(campaign.ROOT))):
            with self.assertRaisesRegex(RuntimeError, 'outside frozen source'):
                campaign.register(self.native, self.base/'state', inside, 'a'*40)
        self.assertFalse(inside.exists())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.native = self.base/'native.bin'
        self.native.write_bytes(b'original reviewed executable')
        self.protocol = self.base/'protocol.md'
        self.protocol.write_bytes(b'frozen protocol')
        self.native_registration = self.base/'native-registration.json'
        self.raw = dict(native_sha256=campaign.sha(self.native),
                        protocol_document_sha256=campaign.sha(self.protocol),
                        source_commit='a'*40, state_directory=str(self.base/'state'))
        self.save_native()
        self.registration = dict(schema=campaign.SCHEMA, source_commit='a'*40,
                                 source_manifest={'schema':'manual-test-only'},
                                 native=str(self.native), native_sha256=self.raw['native_sha256'],
                                 protocol_document_sha256=self.raw['protocol_document_sha256'],
                                 native_registration=str(self.native_registration),
                                 native_registration_sha256=campaign.sha(self.native_registration),
                                 state=str(self.base/'state'))
        for target, replacement in (('PROTOCOL', self.protocol), ('clean', lambda _: None),
                                    ('source_fingerprint.verify', lambda *_: None)):
            context = patch.object(campaign, target, replacement) if '.' not in target else patch('transfer_campaign.'+target, replacement)
            context.start()
            self.addCleanup(context.stop)

    def save_native(self):
        self.native_registration.write_text(json.dumps(self.raw), encoding='utf-8')

    def test_matching_bindings_are_admitted_without_executing_any_target(self):
        native, registration = campaign.preflight(self.registration)
        self.assertEqual((native, registration), (self.native, self.native_registration))
        self.assertFalse((self.base/'state').exists())

    def test_rebuilt_executable_cannot_reuse_registration_even_with_same_source_stamp(self):
        self.native.write_bytes(b'different executable with same claimed stamp')
        with self.assertRaisesRegex(RuntimeError, 'native executable changed'):
            campaign.preflight(self.registration)

    def test_protocol_edits_are_rejected_before_state_creation(self):
        self.protocol.write_bytes(b'posthoc edited protocol')
        with self.assertRaisesRegex(RuntimeError, 'protocol document changed'):
            campaign.preflight(self.registration)
        self.assertFalse((self.base/'state').exists())

    def test_rehashed_inner_registration_cannot_redirect_external_state(self):
        self.raw['state_directory'] = str(self.base/'substituted-state')
        self.save_native()
        self.registration['native_registration_sha256'] = campaign.sha(self.native_registration)
        with self.assertRaisesRegex(RuntimeError, 'bindings differ'):
            campaign.preflight(self.registration)

    def test_changed_source_manifest_refuses_before_native_execution(self):
        with patch('transfer_campaign.source_fingerprint.verify', side_effect=ValueError('source changed')):
            with self.assertRaisesRegex(ValueError, 'source changed'):
                campaign.preflight(self.registration)
        self.assertFalse((self.base/'state').exists())

    def test_sigterm_cancels_owned_synthetic_tree_and_preserves_hold_receipt(self):
        self.registration['artifact_directory'] = str(self.base)
        path = self.base/'campaign-registration.json'
        campaign.write_new(path, self.registration)
        ready = self.base/'synthetic-child-ready.json'
        code = ("import json,pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
                "marker=pathlib.Path(sys.argv[1]);temporary=marker.with_suffix('.tmp');"
                "temporary.write_text(json.dumps({'child_pid':child.pid}),encoding='utf-8');"
                "temporary.replace(marker);time.sleep(30)")
        real_execute = campaign.safety.execute
        signalled = []

        def synthetic_only(argv, directory, label, *, timeout, cancelled):
            self.assertEqual(argv[0], self.native)
            self.assertEqual(argv[1], 'transfer-research')

            def signal_after_owned_child_exists():
                if ready.exists() and not signalled:
                    self.assertNotEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
                    signalled.append(True)
                    signal.raise_signal(signal.SIGTERM)
                return cancelled()

            return real_execute([sys.executable, '-c', code, str(ready)], directory,
                                label+'-synthetic-only', timeout=10,
                                cancelled=signal_after_owned_child_exists)

        before = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
        args = ['transfer_campaign.py', 'run', '--registration', str(path),
                '--registration-sha256', campaign.sha(path)]
        with patch.object(campaign.safety, 'execute', side_effect=synthetic_only) as executed, \
                patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.main(), 1)
            executed.assert_called_once()
        self.assertEqual(signalled, [True])
        self.assertEqual({signum: signal.getsignal(signum) for signum in before}, before)
        report = campaign.load(self.base/'campaign-report.json')
        self.assertEqual(report['status'], 'HOLD')
        self.assertIn('cancelled', report['first_failure'])
        process = report['native_process']
        self.assertEqual(process['outcome'], 'cancelled')
        self.assertTrue(process['cleanup_verified'])
        self.assertNotEqual(process['exit_code'], 0)
        self.assertGreater(campaign.load(ready)['child_pid'], 0)
        self.assertEqual(campaign.load(self.base/process['process_receipt']), process)
        self.assertTrue((self.base/'campaign-started.json').is_file())
        self.assertFalse((self.base/'state').exists())
        self.assertNotIn('independent_process', report)


if __name__ == '__main__':
    unittest.main()
