#!/usr/bin/env python3
import os
import re
from setuptools import find_packages, setup


def get_version(*file_paths):
    """Retrieves the version from encrypted_json_fields/__init__.py"""
    filename = os.path.join(os.path.dirname(__file__), *file_paths)
    version_file = open(filename).read()
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError('Unable to find version string.')


version = get_version("encrypted_json_fields", "__init__.py")
readme = open('README.md').read()
history = open('CHANGELOG.md').read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-encrypted-json-fields',
    version=version,
    packages=find_packages(),
    include_package_data=True,
    license='MIT',
    description='A set of fields that wrap standard Django fields, including JSONField, with encryption provided by the python cryptography library',
    long_description=readme + '\n\n' + history,
    long_description_content_type='text/markdown',
    author='Mario Orlandi',
    author_email='morlandi@brainstorm.it',
    url='https://github.com/morlandi/django-encrypted-json-fields',
    zip_safe=False,
    install_requires=[
        "django >= 2.2",
        "cryptography >= 3.4",
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.8',
    ],
)
