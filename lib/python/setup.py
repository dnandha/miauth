from setuptools import setup, find_packages

# read the contents of your README file
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='miauth',
    version='0.9.6',
    url='https://github.com/dnandha/miauth',
    license='GNU AGPL v3',
    author='Daljeet Nandha',
    author_email='dalj337@gmail.com',
    description='Authenticate and interact with Xiaomi devices over BLE',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(include=['miauth', 'miauth.*']),
    entry_points={
        'console_scripts': ['miauth=miauth.cli:main']
    },
    install_requires=[
        'cryptography'
    ],
    extras_require={
        'cli': [
            'bluepy==1.3.0'
        ]
    },
    python_requires=">=3.6",
)
