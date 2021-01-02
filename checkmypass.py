import requests
import hashlib
import sys

# Key anonymity - modern technique, allow somebody to receive
# information about us yet, without knowing who we are

# Hashing
# - One way, we cannot know the initial data
# - IDEMPOTENT - The same input has the same hash, modified input - new hash


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the API and try againg.')
    # response is a list of tails of hashed passwords, excluding first 5 chars
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':')
              for line in hashes.text.splitlines())  # return a generator
    for hash, count in hashes:
        if hash == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    '''Check password if it exists in API response'''
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_chars, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_chars)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... you should probably change your password.')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'Done!'


# python file.py password1, password2, ...
main(sys.argv[1:])
