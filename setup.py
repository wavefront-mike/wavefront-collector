"""
Setup script for the Wavefront collector tools
"""

import setuptools
import setuptools.command.install

setuptools.setup(
    name='wavefront_collector',
    version='0.0.6',
    author='Wavefront',
    author_email='mike@wavefront.com',
    description=('Wavefront Collector Tools'),
    license='BSD',
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
