import unittest
from pathlib import Path
from analyzer import analyze

class AnalyzerTests(unittest.TestCase):
    def test_sample_and_threshold(self):
        sample=Path(__file__).with_name('sample.log').read_text()
        report=analyze(sample)
        self.assertEqual((report['total'],report['valid'],report['accepted'],report['denied']),(5,5,1,4))
        self.assertEqual(report['findings'],[{'ip':'192.0.2.14','denials':3}])
        self.assertEqual(analyze(sample,4)['findings'],[])
    def test_rejects_bad_time_address_and_html(self):
        result=analyze('25:00:00 DENY 192.0.2.1\n00:00:00 DENY 999.0.0.1\n<img src=x>\n00:00:00 DENY 001.2.3.4')
        self.assertEqual(result['invalid_lines'],[1,2,3,4]); self.assertEqual(result['valid'],0)
    def test_empty_and_invalid_threshold(self):
        self.assertEqual(analyze(' \n')['total'],0)
        for value in [0,-1,True,1.5,100001]:
            with self.assertRaises(ValueError): analyze('',value)
    def test_blank_lines_preserve_line_numbers_and_ties_are_stable(self):
        result=analyze('\nwrong\n00:00:00 DENY 192.0.2.2\n00:00:00 DENY 192.0.2.1',1)
        self.assertEqual(result['invalid_lines'],[2])
        self.assertEqual([f['ip'] for f in result['findings']],['192.0.2.1','192.0.2.2'])

if __name__=='__main__': unittest.main()
