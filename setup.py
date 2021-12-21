from setuptools import setup, find_packages

setup(
    name='miauth',
    version='0.9.1',
    url='https://github.com/dnandha/miauth',
    license='GNU AGPL v3',
    author='Daljeet Nandha',
    author_email='dalj337@gmail.com',
    description='Authenticate and interact with Xiaomi devices over BLE',
    packages=find_packages(include=['miauth', 'miauth.*']),
    entry_points={
        'console_scripts': ['miauth=miauth.cli:main']
    },
    install_requires=[
        'cryptography==36.0.0',
        'bluepy==1.3.0'
    ],
    python_requires=">=3.6",
)
