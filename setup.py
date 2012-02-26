from setuptools import setup, find_packages
import sys, os

version = '0.0.1'

setup(name='cred_thingy',
      version=version,
      description="daemon to create aws credentials for ec2 instances",
      #long_description="""TODO""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Dominic LoBue',
      author_email='dominic.lobue@gmail.com',
      url='',
      license='lgpl',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          "gevent>=0.13.6",
          "paramiko",
          "boto>=2.0rc1",
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )