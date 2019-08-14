from setuptools import setup
setup(name='Security',
	version='1.1.15',
	description='A simple security library wrapping various well known primitives.',
	url='https://www.github.com/pmp47/Security',
	author='pmp47',
	author_email='phil@zeural.com',
	license='MIT',
	packages=['security'],
	install_requires=['bcrypt==3.1.4','secretsharing @ git+https://github.com/blockstack/secret-sharing@master#egg=secret-sharing==0.2.6','pycryptodome==3.7.3'],
	zip_safe=False,
	include_package_data=True,
	python_requires='>=3.6',
	dependency_links=[],

	package_data={'': ['data/*.*']}
)
