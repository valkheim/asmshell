# Run project (for users)

```console
$ sudo apt install poetry
$ poetry install
$ poetry run python .
```

# Run project (for devs)

```console
$ sudo apt install poetry
$ poetry config virtualenvs.in-project true
$ poetry install
$ poetry run pre-commit install
$ poetry run python .
```
