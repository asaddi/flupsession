from setuptools import setup, find_packages
setup(
    name='flupsession',
    version='0.2.2',
    packages=find_packages(),
    install_requires=[
        'six>=1.11.0',
        'cryptography>=2.2.2',
        ],

    author='Allan Saddi',
    author_email='allan@saddi.com',
    description='Simple WSGI middleware for secure (encrypted & signed) cookie-based sessions'
)
