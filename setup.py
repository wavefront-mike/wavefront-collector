"""
Setup script for the Wavefront Integration Tools
"""

import setuptools
import setuptools.command.install

setuptools.setup(
    name='wavefront_integration',
    version='0.0.2',
    author='Wavefront',
    author_email='mike@wavefront.com',
    description=('Wavefront Integration Tools'),
    license='BSD',
    keywords='wavefront',
    url='https://www.wavefront.com',
    install_requires=['wavefront_client', 'python-dateutil', 'logging', 'python-daemon', 'boto3', 'ndg-httpsclient'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Utilities',
        'License :: OSI Approved :: BSD License',
    ],
    package_data={'wavefront': ['data/*']},
    packages=['wavefront'],
    scripts=['wf']
)
