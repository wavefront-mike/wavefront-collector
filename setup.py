"""
Setup script for the Wavefront collector tools.
"""

import setuptools
import setuptools.command.install


# The easiest way to convert the markdown to RestructuredText is to use
# pandoc.  There is a Python frontend to that package called pypandoc.
# To use this code you will need to :
#   1. Download and install pandoc  (http://pandoc.org/installing.html)
#   2. pip install pypandoc
# see: https://coderwall.com/p/qawuyq/use-markdown-readme-s-in-python-modules
try:
    import pypandoc
    LONG_DESCRIPTION = pypandoc.convert_file(source_file='README.md',
                                             format='markdown_github',
                                             to='rst',
                                             extra_args=['-s', '--columns=1000'])
except (IOError, ImportError):
    LONG_DESCRIPTION = ''

setuptools.setup(
    name='wavefront_collector',
    version='0.0.42',
    author='Wavefront',
    author_email='mike@wavefront.com',
    description=('Wavefront Collector Tools'),
    license='BSD',
    long_description=LONG_DESCRIPTION,
    keywords='wavefront wavefront_integration collector metrics',
    url='https://www.wavefront.com',
    install_requires=['wavefront_client', 'python-dateutil', 'logging',
                      'python-daemon', 'boto3', 'ndg-httpsclient'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Utilities',
        'License :: OSI Approved :: BSD License',
    ],
    package_data={'wavefront': ['data/*']},
    packages=['wavefront'],
    scripts=['wf', 'wavefront-collector']
)
