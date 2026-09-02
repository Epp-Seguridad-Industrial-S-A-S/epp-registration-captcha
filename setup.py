# pylint: disable=open-builtin
from __future__ import absolute_import, print_function, unicode_literals

import os

from setuptools import find_packages, setup

from version import __version__

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))


def load_requirements(*requirements_paths):
    """Load all requirements from the specified requirements files."""
    requirements = set()
    for path in requirements_paths:
        requirements.update(
            line.split("#")[0].strip() for line in open(path).readlines() if is_requirement(line.strip())
        )
    return list(requirements)


def is_requirement(line):
    """Return True if the requirement line is a package requirement (not a comment/URL/include)."""
    return not (
        line == ""
        or line.startswith("-c")
        or line.startswith("-r")
        or line.startswith("#")
        or line.startswith("-e")
        or line.startswith("git+")
    )


README = open(os.path.join(os.path.dirname(__file__), "README.md")).read()
CHANGELOG = open(os.path.join(os.path.dirname(__file__), "CHANGELOG.rst")).read()

setup(
    name="epp-registration-captcha",
    version=__version__,
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    license="Proprietary",
    description="Server-side Google reCAPTCHA verification for the Open edX self-registration flow.",
    long_description=README + "\n\n" + CHANGELOG,
    author="Epp Seguridad Industrial S.A.S.",
    author_email="jcguerragarcia8@gmail.com",
    url="https://github.com/Epp-Seguridad-Industrial-S-A-S/epp-registration-captcha.git",
    install_requires=load_requirements("requirements/common.in"),
    zip_safe=False,
    keywords="Django, Open edX, reCAPTCHA, registration",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
)
