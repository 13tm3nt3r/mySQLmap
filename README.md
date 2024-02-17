# mySQLmap
mySQLmap is a simple program created to detect Blind-based SQL Injections in certain sites. Currently, it is useful to list databases, as more functionalities such as list tables, users and so on, are future work.

## Requirements
This tool has been developed with **Python v3.11**, it is not guaranteed to work properly with any other version.

## Installation
```
1. git clone `this_repo`
2. cd ./mySQLmap
3. python3 -m pip install -r requirements.txt
4. python3 mySQLmap.py -h
```

## Examples
- Using the required parameters:
```
python3.11 mySQLmap.py -u 'http://<IP>/vulnerabilities/sqli_blind/?id=1&Submit=Submit' -g id
```
- Using cookies to avoid login page:
```
python3.11 mySQLmap.py -u 'http://<IP>/vulnerabilities/sqli_blind/?id=1&Submit=Submit' -g id -c 'PHPSESSID=92q1himd399sfscvo9c06d5eko,security=low'
```