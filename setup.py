from setuptools import setup, Extension

setup(
    name="wiper", 
    ext_modules=[Extension("_wiper", ["_wiper.c"])]
)
