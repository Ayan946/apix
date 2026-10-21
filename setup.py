from setuptools import setup

setup(
    name="apix",
    version="1.0",
    py_modules=["main"],
    packages=["apix"],
    install_requires=["requests", "pyjwt"],
    entry_points={"console_scripts": ["apix=main:main"]},
)
