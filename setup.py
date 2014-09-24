#coding: utf-8

import os
from setuptools import setup


def read(fn):
    return open(os.path.join(os.path.dirname(__file__), fn)).read()

setup(
    name='m3-libsmev',
    version='0.1.6.4',
    author='Borisov Kirill',
    author_email='borisov@bars-open.ru',
    description=("Library of low-level helpers that make integration with SMEV "
                 "somewhat less painful"),
    license="MIT",
    keywords="smev m3 bars",
    long_description=read('README.rst'),
    packages=['libsmev'],
    install_requires=['lxml >= 3.1.0'],
    classifiers=(
        'Intended Audience :: Developers',
        'Environment :: Web Environment',
        'Natural Language :: Russian',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Development Status :: 5 - Production/Stable',
    )
)
