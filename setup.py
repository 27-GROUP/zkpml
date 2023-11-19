from setuptools import setup, find_packages

setup(
    name='mcypher',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        cryptography
    ],
    # additional metadata
    author='Mamadou K. KEITA',
    author_email='mk.ai.researcher@gmail.com',
    description='SecureEncryption is a Python script that provides a straightforward interface for RSA-AES hybrid encryption. It allows users to encrypt a message using a combination of RSA and AES-GCM encryption and subsequently decrypt it.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/27-GROUP/zkpml',
)

