#!/usr/bin/python3 -su

## Copyright (C) 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Asserts that the troubleshooting output does not carry proxy credentials.
## The check is that the secret VALUE is absent from what gets printed, not
## merely that a redaction function exists.

import io
import os
import sys
import contextlib
import tempfile
import unittest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '..', '..', '..', 'lib', 'python3', 'dist-packages'))

from tor_control_panel import tor_status

secret = 'hunter2SuperSecretValue'

torrc_sample = f"""\
UseBridges 1
Socks5Proxy 192.0.2.1:1080
Socks5ProxyUsername alice
Socks5ProxyPassword {secret}
   HTTPSProxyAuthenticator alice:{secret}
HashedControlPassword 16:AAAA{secret}
"""


class TestRedactCredentials(unittest.TestCase):

    def test_secret_value_absent(self):
        redacted = tor_status.redact_credentials(torrc_sample)
        self.assertNotIn(secret, redacted)

    def test_option_names_kept(self):
        ## The log must still show WHICH options were set; only the value goes.
        redacted = tor_status.redact_credentials(torrc_sample)
        for option in ('Socks5ProxyUsername', 'Socks5ProxyPassword',
                       'HTTPSProxyAuthenticator', 'HashedControlPassword'):
            self.assertIn(option, redacted)
            self.assertIn(f'{option} [REDACTED]', redacted)

    def test_non_credential_lines_untouched(self):
        redacted = tor_status.redact_credentials(torrc_sample)
        self.assertIn('UseBridges 1', redacted)
        ## The proxy address is not a credential and stays readable, which is
        ## what makes the output useful for troubleshooting.
        self.assertIn('Socks5Proxy 192.0.2.1:1080', redacted)

    def test_case_insensitive_and_indented(self):
        redacted = tor_status.redact_credentials(
            f'  socks5proxypassword {secret}\n')
        self.assertNotIn(secret, redacted)

    def test_cat_output_redacted(self):
        ## Integration: the real cat() is one of the two functions that print
        ## torrc content, so it is exercised rather than only the helper.
        with tempfile.NamedTemporaryFile('w', suffix='.conf',
                                         delete=False) as torrc_file:
            torrc_file.write(torrc_sample)
            torrc_path = torrc_file.name
        try:
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                tor_status.cat(torrc_path)
            self.assertNotIn(secret, captured.getvalue())
            self.assertIn('Socks5ProxyPassword [REDACTED]',
                          captured.getvalue())
        finally:
            os.unlink(torrc_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
