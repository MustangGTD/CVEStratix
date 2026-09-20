import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main as m
from rich.console import Console


def service():
    return dict(port=80, service='http', product='Apache httpd', version='2.4.49',
                cpes=['cpe:/a:apache:http_server:2.4.49'], tunnel='', extra='', protocol='tcp')


def record(version='2.4.49'):
    return dict(id='CVE-2021-41773', published='2021-10-05', descriptions=[{'lang': 'en', 'value': 'Example'}],
                configurations=[{'nodes': [{'cpeMatch': [{'vulnerable': True,
                'criteria': 'cpe:2.3:a:apache:http_server:' + version + ':*:*:*:*:*:*:*'}]}]}])


class Tests(unittest.TestCase):
    def test_ports(self):
        self.assertEqual(m.ports('22,80,3000'), '22,80,3000')
        for value in ('80;id', '0', '65536', '90-80', '--script'):
            with self.assertRaises(Exception):
                m.ports(value)

    def test_cpe(self):
        q, fields = m.query_for(service())
        self.assertIn('virtualMatchString', q)
        self.assertEqual(len(fields), 11)
        self.assertIsNone(m.normalize_cpe('cpe:/a:vendor:product:1.0:~packed'))

    def test_no_version(self):
        s = service()
        s.update(version='', cpes=[])
        self.assertEqual(m.query_for(s), (None, None))

    def test_exact_and_mismatch(self):
        fields = m.query_for(service())[1]
        self.assertEqual(m.applicability(record(), fields)[0], 'VERSION EVIDENCE FOUND')
        self.assertEqual(m.applicability(record('2.4.50'), fields)[0], 'VERSION MISMATCH')

    def test_ranges(self):
        self.assertTrue(m.range_check('2.4.49', {'versionEndExcluding': '2.4.50'}))
        self.assertFalse(m.range_check('2.4.50', {'versionEndExcluding': '2.4.50'}))
        self.assertTrue(m.range_check('2.4', {'versionStartIncluding': '2.4.0'}))
        self.assertIsNone(m.range_check('8.2p1', {'versionEndExcluding': '8.3'}))

    def test_configuration_not_confirmed(self):
        item = m.finding(record(), m.query_for(service())[1])
        self.assertIn('not verified', item['prerequisites'])
        self.assertIn('Not independently verified', item['fixed_version'])

    def test_pagination(self):
        with patch.object(m.NVD, 'page', side_effect=[
            {'totalResults': 2, 'vulnerabilities': [{'cve': {'id': 'CVE-1'}}]},
            {'totalResults': 2, 'vulnerabilities': [{'cve': {'id': 'CVE-2'}}]},
        ]) as mock:
            c = m.NVD()
            records, status = c.fetch({'keywordSearch': 'test'})
            c.session.close()
            self.assertEqual(len(records), 2)
            self.assertTrue(status['complete'])
            self.assertEqual(mock.call_args.args[0]['startIndex'], 1)

    def test_partial_failure(self):
        with patch.object(m.NVD, 'page', side_effect=[
            {'totalResults': 2, 'vulnerabilities': [{'cve': {'id': 'CVE-1'}}]},
            RuntimeError('offline'),
        ]):
            c = m.NVD()
            records, status = c.fetch({})
            c.session.close()
            self.assertFalse(status['complete'])
            self.assertEqual(len(records), 1)

    def test_xml(self):
        raw = '<nmaprun><host><address addr="192.0.2.1"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port><port protocol="tcp" portid="80"><state state="closed"/></port></ports></host></nmaprun>'
        self.assertEqual(len(m.parse_scan(raw, '192.0.2.1')), 1)
        self.assertEqual(m.parse_scan(raw, '192.0.2.2'), [])

    def test_ipv6_commands(self):
        s = service()
        s.update(tunnel='ssl', port=443)
        self.assertIn('-6', m.commands('::1', s)[0]['command'])
        self.assertIn('https://[::1]:443/', m.commands('::1', s)[1]['command'])

    def test_full_scan_command(self):
        from unittest.mock import MagicMock
        child = MagicMock()
        child.stdout = []
        child.wait.return_value = 0
        child.poll.return_value = 0
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'scan.xml').write_text('<nmaprun/>')
            with patch.object(m.shutil, 'which', return_value='/usr/bin/nmap'), patch.object(m.subprocess, 'Popen', return_value=child) as start:
                m.scan('::1', '1-65535', Path(d))
                cmd = start.call_args.args[0]
                self.assertIn('1-65535', cmd)
                self.assertIn('-6', cmd)
                self.assertNotIn('--script', cmd)

    def test_web_no_redirect(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.status_code = 302
        response.headers = {'Location': 'https://elsewhere.invalid/'}
        response.encoding = 'utf-8'
        response.iter_content.return_value = [b'<title>Example</title>']
        context = MagicMock()
        context.__enter__.return_value = response
        with patch.object(m.requests, 'get', return_value=context) as get:
            result = m.web_evidence('192.0.2.1', service())
            self.assertEqual(result['title'], 'Example')
            self.assertFalse(get.call_args.kwargs['allow_redirects'])
            self.assertNotIn('verify', get.call_args.kwargs)


    def test_uncertain_port_3000_is_web_candidate(self):
        s = dict(port=3000, service='ppp', product='', version='', cpes=[],
                 tunnel='', extra='', protocol='tcp')
        self.assertTrue(m.web_candidate(s))

    def test_juice_shop_fingerprint_and_promotion(self):
        s = dict(port=3000, service='ppp', product='', version='', cpes=[],
                 tunnel='', extra='', protocol='tcp')
        fp = m.identify_web_application(
            'OWASP Juice Shop',
            'Copyright (c) Bjoern Kimminich & the OWASP Juice Shop contributors.',
            {}
        )
        self.assertEqual(fp['application'], 'OWASP Juice Shop')
        self.assertEqual(fp['confidence'], 'HIGH')
        s['web'] = {'fingerprint': fp}
        m.enrich_service_from_web(s)
        self.assertEqual(s['service'], 'http')
        self.assertEqual(s['nmap_service'], 'ppp')
        self.assertEqual(s['product'], 'OWASP Juice Shop')
        self.assertEqual(s['detected_application'], 'OWASP Juice Shop')

    def test_text_not_markup(self):
        output = io.StringIO()
        with patch.object(m, 'console', Console(file=output)):
            m.say('[red]untrusted[/red]')
        self.assertIn('[red]', output.getvalue())

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as d, patch.object(m, 'console', Console(file=io.StringIO(), record=True)), patch.object(m, 'scan', return_value=[service()]), patch.object(m, 'web_evidence', return_value=None), patch.object(m.NVD, 'fetch', return_value=([record()], {'complete': True})), patch('sys.argv', ['main.py', '192.0.2.1', '--output', d]):
            self.assertEqual(m.main(), 0)
            report = list(Path(d).glob('*/report.txt'))[0].read_text()
            self.assertIn('CVE-2021-41773', report)
            self.assertIn('searchsploit', report)
            self.assertIn('Mitigation', report)
            self.assertTrue(list(Path(d).glob('*/report.json')))


if __name__ == '__main__':
    unittest.main()
