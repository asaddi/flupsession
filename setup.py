from setuptools import setup, find_packages
setup(
    name='flupsession',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'cryptography>=2.2.2',
        ],

    author='Allan Saddi',
    author_email='allan@saddi.com',
    description='Simple WSGI middleware for secure (encrypted & signed) cookie-based sessions'
)
