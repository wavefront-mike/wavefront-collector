import mock
import sys
import unittest

sys.path.append('..')
from wavefront.system_checker import SystemCheckerCommand

def literal(**kw):
    return namedtuple('literal', kw)(**kw)

class TestSystemCheckerCommand(unittest.TestCase):

    def test_execute_without_config(self):
        """
        Tests that execute() returns with error when --config is not provided
        """

        cmd = SystemCheckerCommand()
        args = {}
        with self.assertRaises(ValueError):
            cmd.execute(args)

    def test_execute_with_no_sections(self):
        cmd = SystemCheckerCommand()
        args = literal(config_file_path = '/tmp/system_checker.conf')
        m = mock.mock_open(read_data='[global]\n')
        with mock.patch('__main__.open', m, create=True):
            cmd.execute(args)
        
if __name__ == '__main__':
    unittest.main()
