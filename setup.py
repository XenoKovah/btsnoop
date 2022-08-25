import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="btsnoop",
    version="1.0.1",
    author="Travis Peters",
    author_email="traviswp@gmail.com",
    description="A Bluetooth HCI traffic snooping and parsing module.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/traviswpeters/btsnoop",
    packages=setuptools.find_packages(),
    classifiers=[
        "Bluetooth :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Linux",
    ],
)
