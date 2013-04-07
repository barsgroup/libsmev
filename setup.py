#coding: utf-8

import os
from setuptools import setup


def read(fn):
    return open(os.path.join(os.path.dirname(__file__), fn)).read()

setup(
    name='libsmev',
    version='0.1.0',
    author='Borisov Kirill',
    author_email='borisov@bars-open.ru',
    description=("Library of low-level helpers that make integration with SMEV"
                 "somewhat less paingful"),
    license="BSD",
    keywords="lxml smev m3 bars",
    long_description=read('README'),
    packages=['libsmev'],
    install_requires=['libxml2-python >= 2.6.9', 'lxml >= 3.1.0'],
    classifiers=(
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Natural Language :: Russian',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.6',
        'Topic :: Software Development :: Libraries',
        'Topic :: Utilities')
)
