from . import *

import tomcrypt


class TestVersion(TestCase):

    def test_setup_version(self):

        setup_py = os.path.abspath(os.path.join(__file__, '..', '..', 'setup.py'))
        proc = Popen(['python', setup_py, '--version'], stdout=PIPE)
        out, _ = proc.communicate()

        self.assertEqual(out.strip(), tomcrypt.__version__)

    def test_docs_version(self):

        conf_py = os.path.abspath(os.path.join(__file__, '..', '..', 'docs', 'conf.py'))
        namespace = {}
        execfile(conf_py, namespace)

        self.assertEqual(namespace['release'], tomcrypt.__version__)

        real = tomcrypt.__version__.split('.')
        docs = namespace['version'].split('.')
        self.assertEqual(docs, real[:len(docs)])
        

