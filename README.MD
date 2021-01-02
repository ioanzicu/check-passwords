# Check if the Passwords was not leaked 

## Prerequisits
- [Python 3](https://www.python.org/downloads/)
- pipenv package
    ```bash
    pip3 install pipenv
    ```


## Install
1. Open **pipenv** shell
    ```bash
    pipenv shell
    ```
2. Install Dependencies
    ```bash
    pipenv install
    ```
3. Run the project from the root folder, having **pipenv** activated
    ```bash
    python check_passwords.py password1, password2, ..., passwordN
    ```