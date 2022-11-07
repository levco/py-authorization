from setuptools import find_packages, setup

setup(
    author="Lucas Forchino, Getulio Valentin Sanchez",
    url="http://github.com/levco/py-authorization",
    author_email="lf@lev.co, gs@lev.co",
    packages=find_packages(),
    package_data={
        "py_authorization": ["py.typed", "*.pyi"],
    },
)
