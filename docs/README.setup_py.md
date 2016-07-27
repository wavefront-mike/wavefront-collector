# Prerequisites
- ~/.pypirc file
```
[distutils]
index-servers =
  pypi
  pypitest

[pypi]
repository: https://pypi.python.org/pypi
username: wavefront-cs
password: _hidden_

[pypitest]
repository: https://testpypi.python.org/pypi
username: wavefront-cs
password: _hidden_
```

- Pypandoc and pandoc installed
```
> brew install pandoc
> pip install pypandoc
```

# Steps to check and update this script on PyPi

1. Check the README.md file is OK
    ```
    > python setup.py check -rs
    ```
2. Update the version number in setup.py
3. Build and upload latest
    ```
    > python setup.py clean build sdist upload -r pypi
    ```
4. Check the PyPi page 
    ```
    https://pypi.python.org/pypi?:action=display&name=wavefront_collector&version=NEW_VERSION_HERE
    ```
