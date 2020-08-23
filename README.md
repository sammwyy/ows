# OWS
The online-with-security project is a small cyber security manuscript for the prevention of computer attacks.

## Introduction
Most of the cases a "Hack" is executed successfully it's because bad practices had been done when developing the public interface of your application thus letting anyone "Exploit" that.
  
In this guide we will see a summary of the most common problems in terms of web security and how to solve them.  
  
This guide will not ensure that your service is 100% inpenetrable but it will greatly decrease the possibilities and as long as there are no human errors then there would be no need to worry and remember not only to look at the security of what your programs but also what you use. (libraries, frameworks, technologies)  

### Arbitrary Library Injection
**Danger level:** High  
**Environment:** MySQL  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** A remote authenticated user with INSERT privileges can exploit this vulnerability to bypass UDF library path restrictions. This may allow an attacker to execute arbitrary code, with the privileges of mysqld, by calling functions in arbitrary shared libraries.

### Application Configuration
**Danger level:** Medium  
**Environment:** System  
**Type of threat:** Several 
**Explanation:** Bad configuration of the server/system with default passwords, libraries or dependencies with security flaws, outdated system and active and open debugging functions.

### Arbitrary Code Execution
**Danger level:** Medium  
**Environment:** System  
**Type of threat:** --  
**Explanation:** We know by ACE (Arbitrary Execution Code) when a system allows us to inject instructions that will be executed in the program in an arbitrary/external way, taking advantage of bugs in it to overwrite its default routine.

### Buffer Overflow
**Danger level:** High  
**Environment:** System  
**Type of threat:** Memory  
**Explanation:** When a program does not adequately control the data that will be written to the ram, a buffer overflow could occur. This is because a space must be allocated in the ram with the right size of the data that we are going to enter but if the size of the data exceeds the size assigned in the ram, it will be saved in another position over writing what was originally in her.

### Code Injection
**Danger level:** High  
**Environment:** HTTP and Applications  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** Code injection happens when a user can run arbitrary code on the server side, either because the server evaluates a highly privileged expression from a form or from a value that the user can easily alter.

### Cookie Injection
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** We call cookie injection the action of manipulating the data that is stored in the browser when visiting a website. If the web is badly programmed and it does not verify the input of the cookie before reading it, there could be a case of SQL injection or arbitrary code execution.

### Command Injection
**Danger level:** High  
**Environment:** HTTP and System  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** Command injection occurs when system commands are executed based on a string formed by a parameter specified by the user. If it is not controlled or sanitized, the user could take advantage of this vulnerability to run native commands in the operating system.

### Cookie Without 'HttpOnly' Flag
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** XSS (Cross site scripting)  
**Explanation:** If we do not set the "http only" flag to the cookies of our website then they will be exposed to XSS attacks which the threat is client side or by a security breach in the website that allows the attacker to modify a request or to inject an element external to the original website.

### Cross-Site Scripting
**Danger level:** Medium  
**Environment:** HTTP  
**Type of threat:** --  
**Explanation:** We know by XSS (Cross site scripting) when we can manipulate the JS functions of a website on the client side, executing actions on behalf of the user, compromising the integrity of the same.

### Dangerous File Extensions
**Danger level:** Low  
**Environment:** JSP, PHP, ASP and others Script based websites  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** When creating a system to upload files if we are not careful we can make the mistake of not filtering or validating the files uploaded to the server and for example uploading a software script that when entering through its url executes arbitrary code on the server (an example of this would be .php files that are script-run server-side when loaded by url)  

### Dangerous HTML Embedded
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** XSS (Cross site scripting)  
**Explanation:** By attaching an external widget to a website we are opening the possibility of executing arbitrary code on the user's client, ending this in a possible XSS attack. This will allow the attacker to obtain the data stored by the website such as cookies and execute actions under the identity of the same user.

### Deserialization of Untrusted Data
**Danger level:** High  
**Environment:** Several  
**Type of threat:** DoS and ACE  
**Explanation:** The deserialization of unreliable data is based on deserializing an input from a user which is planned to return a specific object but it is not validated that the result will be as expected. For example, trying to parse a string to a classy object, if the string does not have the format of that class, it could be the case of a DoS internally, leading the application to close or in the worst case, it could be exploited to execute arbitrary code.

### DOM Based Cross-Site Scripting
**Danger level:** Medium  
**Environment:** HTTP  
**Type of threat:** XSS (Cross site scripting)  
**Explanation:** If we evaluate code that comes from parameters given by the user or by parameters of the url then the website is vulnerable to DBXSS (DOM Based Cross-Site Scripting) which allows us to inject javascript functions to pages that manipulate the dom with innerHTML or they evaluate with eval what is entered by the same user.

### Error Messages Information Exposure
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** Disclosure  
**Explanation:** Informational error messages are messages that the server returns when an unhandled exception occurs or a handled exception that displays its message on the screen. This is usually because you are working in a development environment and not a production environment.

### File Manipulation
**Danger level:** Medium  
**Environment:** HTTP  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** We must sanitize the files that the server receives because although a browser sends valid files, a malicious program can send files with names like these: "../../file.txt" which is an invalid name for a file but the server interprets it as a path and would save it 2 levels higher than the original.

### FTP Command Injection
**Danger level:** Low  
**Environment:** Ruby  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** Some older versions of ruby can be exploited with malicious files that contain instructions that, when loaded by HTTP, are executed as a payload.

### Heap Inspection
**Danger level:** Low  
**Environment:** Memory & Java  
**Type of threat:** Dump  
**Explanation:** It is common for strings to contain confidential text that is not encrypted, but an attacker can do a memory dump if he has access to the vulnerable system and the in-memory string could be revealed. The memory could also be dumped as a result of an exploit that exhausts the system resources before the GC (Garbage Collector) removes them, because the strings are an immutable object, they will not disappear from memory until the GC removes them.

### HTTP Response Splitting
**Danger level:** Medium  
**Environment:** HTTP  
**Type of threat:** XSS & CRLF  
**Explanation:** You can inject data into the HTTP header by querying GET parameters using special characters. An example is to inject or obtain cookies by placing a function in the request url so that the server returns a response modified by that parameter. Example `http:/example.com/redirect.asp?origin=foo%0d%0aSet-Cookie:%20ASPSESSIONIDACCBBTCD=SessionFixed%0d%0a`

### Insecure Data Storage
**Danger level:** High  
**Environment:** HTTP and Applications  
**Type of threat:** Data Leak  
**Explanation:** In the event of a security breach, if data is stored insecurely, attackers can obtain confidential user data. For this, the ideal is to store data such as passwords encrypted with one-way algorithms.

### Insufficient Transport Layer Protection
**Danger level:** High  
**Environment:** HTTP  
**Type of threat:** MitM (Man in the middle)  
**Explanation:** This vulnerability occurs when the connection between the user and the server is not secure, for example when the HTTP protocol is being used and not HTTPS (Without TLS / SSL)

### Integer Overflow
**Danger level:** High  
**Environment:** System  
**Type of threat:** Data Injection  
**Explanation:** If an integer exceeds the allowed limit it will become the minimum allowed or 0. An example, if an integer exceeds the number 2,147,483,647 (which is the maximum of the int32) then it will become -2,147,483,647 (the same but negative)

### Integer Underflow
**Danger level:** Medium  
**Environment:** System  
**Type of threat:** Data Injection  
**Explanation:** Integer Underflow we can call an exploit which an application or system accepts an integer value below the minimum allowed creating a contrary operation. For example if we add 10 and 10 it would be 20, if we add 4 and 10 it will be 14., no matter what we add to 10, it will always be higher than the original but if we add for example -4 (a negative number) this operation would be done : -4 + 10 which would give a value of 6.

### Mail Open-Relay
**Danger level:** Low  
**Environment:** System & Mail  
**Type of threat:** Spoofing  
**Explanation:** Open-Relay vulnerability is known to a vulnerability that is present in mail servers that allows anyone to send emails from the server without any type of restriction, opening the door to identity theft.

### Mass Assignment
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** Data Injection  
**Explanation:** We can violate uncontrolled forms to modify fields that should not be altered in the first place. In an example, a registration form that has 3 fields; Username, email and password. On the server side, we have a user schema that saves 4 data; Username, email, password and if this is an administrator or not. (Usually this last value is altered from a control panel) Then, the exploit would allow us to send in the request also the value of admin to set it to true and not by default which would be false.

### MITM Attacks (Man in the Middle)
**Danger level:** High  
**Environment:** Networking  
**Type of threat:** --
**Explanation:** A mitm attack is when the attacker is in the middle of the client and the server interfering with the data sent and received.

### PHP File Inclusion
**Danger level:** High  
**Environment:** PHP  
**Type of threat:** ACE  
**Explanation:** If we include a file in php that comes from a user input then we will be exposed to an attacker being able to read the content of any file.

### Path/Directory Traversal
**Danger level:** High  
**Environment:** HTTP  
**Type of threat:** Data Leak  
**Explanation:** This exploit occurs when the user must specify the name of a file to read, then an attacker can modify the file name in this way "../../../file.txt" to read files outside the specified directory .

### Regex Denial of Service (ReDoS)
**Danger level:** Medium  
**Environment:** System  
**Type of threat:** DoS (Denial of Service)   
**Explanation:** This type of denial of service is done from inside the server when trying to evaluate an expression that would take a lot of time and resources to resolve.

### Sensitive Case Database
**Danger level:** Low  
**Environment:** Database  
**Type of threat:** Spoofing  
**Explanation:** There are cases where we forget that the default databases are sensitive, that is to say that if we store something in lowercase we cannot obtain it with a query being in uppercase and vice versa. A case of insecure application would be when the user "john" is registered and when trying to register again the user "john" it says that it is already in the database but when registering "jOhn" (using capital letters) it does allow us doing it.

### Server Side Request Forgery
**Danger level:** High  
**Environment:** Server  
**Type of threat:** ASSR (Arbitrary Server Side Request)  
**Explanation:** This vulnerability occurs when a user can send requests from the server to a remote host. This way you can connect to servers within a DmZ bypassing the firewall.

### Session Fixation
**Danger level:** Medium  
**Environment:** HTTP  
**Type of threat:** Hijack  
**Explanation:** This exploit is based on modifying the unique identifier of a user so that it is logged in and the session token is saved with a wrong id, in this way an attacker can set the id of a user for example with the url and steal their credentials. Example: `http://example.com/?PHPSESSID=123456`

### SQL Injection
**Danger level:** High  
**Environment:** Database  
**Type of threat:** --  
**Explanation:** An sql injection occurs when a SQL query is made which includes an input without sanitizing. This leaves the door open to manipulating the SQL query by remotely manipulating the database.

### System Properties Disclosure
**Danger level:** Low  
**Environment:** System & Software  
**Type of threat:** Disclosure  
**Explanation:** This exploit is due to the fact that an application or software is exposing system data such as the same software and version that are being used, operating system or hardware components.

### System Properties Change
**Danger level:** Medium  
**Environment:** System  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** The exploits that allow manipulating the operating system parameters are called System Properties Change.

### Uncontrolled Memory Allocation
**Danger level:** Medium  
**Environment:** System  
**Type of threat:** Memory  
**Explanation:** The exploit is based on saving data in memory whose size is out of the allowed, in this way more data will be stored than controlled.

### Unrestricted File Upload
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** Several  
**Explanation:** If we do not control the upload of files to the server, we can make the mistake of allowing the upload of a script that is executed server-side, an asset that is executed client-side or application errors or libraries such as buffer-overflow, arbitrary code execution, cross site scripting, hijacking, vulnerable antivirus software, malware flaw exploit, FsDOS or change the path where the file will be saved by modifying its metadata or replacing a vital file on the system where it will be saved.

### Unvalidated/Open Redirect
**Danger level:** Medium  
**Environment:** HTTP  
**Type of threat:** Phishing & XSS  
**Explanation:** This exploit is present in the redirection endpoints of websites, for example an attacker could manipulate the destination url field to place a phishing, something like this: `https://example.com/redirect.php?redirecturl=http://phishing.com/`.

### Weak Encryption Strength
**Danger level:** Low  
**Environment:** Database  
**Type of threat:** Hashing  
**Explanation:** It is possible to break encryptions if the algorithm to be used is weak. It could be obtained with a dictionary and / or doing reverse engineering to the same algorithm.
