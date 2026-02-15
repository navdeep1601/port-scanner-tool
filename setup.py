from setuptools import setup, find_packages

setup(
    name='port-scanner-tool',
    version='1.0.0',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=[
        'dnspython',
        'jinja2',
    ],
    entry_points={
        'console_scripts': [
            'port-scanner=port_scanner:main',
        ],
    },
    author='Your Name',
    author_email='your.email@example.com',
    description='Enhanced port scanner for reconnaissance',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/port-scanner-tool',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)