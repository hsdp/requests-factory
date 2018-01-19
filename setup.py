from setuptools import setup, find_packages
from os import path

with open(path.join(path.dirname(__file__), 'requirements.txt')) as f:
    reqs = [l for l in f.read().strip().split('\n') if not l.startswith('-')]

with open(path.join(path.dirname(__file__), 'version.txt')) as f:
        __version__ = f.read().strip()

setup(
    name='requests_factory',
    version=__version__,
    description='HTTP Request Builder based on requests Library',
    long_description=open('README.md').read(),
    license=open('LICENSE').read(),
    author='Adam Jaso',
    author_email='ajaso@hsdp.io',
    packages=['requests_factory'],
    package_dir={
        'requests_factory': 'requests_factory',
    },
    install_requires=reqs,
    url='https://github.com/hsdp/requests-factory',
)
