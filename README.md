# OWS
The online-with-security project is a small cyber security manuscript for the prevention of computer attacks.

## Introduction
Computer hackers in most cases are due to bad practices when programming a system that will be available to any user via the internet.  
  
In this guide we will see a summary of the most common problems in terms of web security and how to solve them.  
  
This guide will not ensure that your service is 100% inpenetrable but it will greatly decrease the possibilities and as long as there are no human errors then there would be no need to worry and remember not only to look at the security of what your programs but also what you use. (libraries, frameworks, technologies)  

### Application Configuration
**Danger level:** Medium  
**Environment:** System  
**Type of threat:** Several 
**Explanation:** Bad configuration of the server/system with default passwords, libraries or dependencies with security flaws, outdated system and active and open debugging functions.

### Arbitrary Code Execution
**Danger level:** Medium  
**Environment:** Any  
**Type of threat:** --  
**Explanation:** We know by ACE (Arbitrary Execution Code) when a system allows us to inject instructions that will be executed in the program in an arbitrary/external way, taking advantage of bugs in it to overwrite its default routine.

### Cookie Injection
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** We call cookie injection the action of manipulating the data that is stored in the browser when visiting a website. If the web is badly programmed and it does not verify the input of the cookie before reading it, there could be a case of SQL injection or arbitrary code execution.

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
**Explanation:** When creating a system to upload files if we are not careful we can make the mistake of not filtering or validating the files uploaded to the server and for example uploading a software script that when entering through its url executes arbitrary code + odigo on the server (an example of this would be .php files that are script-run server-side when loaded by url)  

### Dangerous HTML Embedded
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** XSS (Cross site scripting)  
**Explanation:** By attaching an external widget to a website we are opening the possibility of executing arbitrary code on the user's client, ending this in a possible XSS attack. This will allow the attacker to obtain the data stored by the website such as cookies and execute actions under the identity of the same user.

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
**Type of theat:** ACE (Arbitrary code execution)  
**Explanation:** We must sanitize the files that the server receives because although a browser sends valid files, a malicious program can send files with names like these: "../../file.txt" which is an invalid name for a file but the server interprets it as a path and would save it 2 levels higher than the original.

### FTP Command Injection
**Danger level:** Low  
**Environment:** Ruby  
**Type of threat:** ACE (Arbitrary code execution)  
**Explanation:** Some older versions of ruby can be exploited with malicious files that contain instructions that, when loaded by HTTP, are executed as a payload.

### Heap Inspection
**Danger level:** Low  
**Environment:** System & Java  
**Type of threat:** Dump  
**Explanation:** It is common for strings to contain confidential text that is not encrypted, but an attacker can do a memory dump if he has access to the vulnerable system and the in-memory string could be revealed. The memory could also be dumped as a result of an exploit that exhausts the system resources before the GC (Garbage Collector) removes them, because the strings are an immutable object, they will not disappear from memory until the GC removes them.

### HTTP Response Splitting
**Danger level:** Medium  
**Environment:** HTTP  
**Type of threat:** XSS & CRLF  
**Explanation:** You can inject data into the HTTP header by querying GET parameters using special characters. An example is to inject or obtain cookies by placing a function in the request url so that the server returns a response modified by that parameter. Example `http:/example.com/redirect.asp?origin=foo%0d%0aSet-Cookie:%20ASPSESSIONIDACCBBTCD=SessionFixed%0d%0a`

### Integer Underflow
**Danger level:** Medium  
**Environment:** System  
**Type of theat:** Data Injection  
**Explanation:** Integer Underflow we can call an exploit which an application or system accepts an integer value below the minimum allowed creating a contrary operation. For example if we add 10 and 10 it would be 20, if we add 4 and 10 it will be 14., no matter what we add to 10, it will always be higher than the original but if we add for example -4 (a negative number) this operation would be done : -4 + 10 which would give a value of 6.

### Intents Usage
**Danger level:** Medium  

### Location Information
**Danger level:** Medium  

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

### Regex Denial of Service (ReDoS)
**Danger level:** Medium  

### Sensitive Case Database
**Danger level:** Low  
**Environment:** Database  
**Type of threat:** Spoofing  
**Explanation:** There are cases where we forget that the default databases are sensitive, that is to say that if we store something in lowercase we cannot obtain it with a query being in uppercase and vice versa. A case of insecure application would be when the user "john" is registered and when trying to register again the user "john" it says that it is already in the database but when registering "jOhn" (using capital letters) it does allow us doing it.

### Session Fixation
**Danger level:** Medium  

### Session Poisoning
**Danger level:** Medium  

### Sleep Denial Of Service
**Danger level:** Medium  

### System Properties Disclosure
**Danger level:** Low  
**Environment:** System & Software  
**Type of threat:** Disclosure  
**Explanation:** This exploit is due to the fact that an application or software is exposing system data such as the same software and version that are being used, operating system or hardware components.

### System Properties Change
**Danger level:** Medium  

### Trust Boundary Violation
**Danger level:** Medium  

### Uncontrolled Memory Allocation
**Danger level:** Medium  

### Unrestricted File Upload
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** Several  
**Explanation:** If we do not control the upload of files to the server, we can make the mistake of allowing the upload of a script that is executed server-side, an asset that is executed client-side or application errors or libraries such as buffer-overflow, arbitrary code execution, cross site scripting, hijacking, vulnerable antivirus software, malware flaw exploit, FsDOS or change the path where the file will be saved by modifying its metadata or replacing a vital file on the system where it will be saved.

### Unvalidated/Open Redirect
**Danger level:** Medium  

### Weak Encryption Strength
**Danger level:** Low  
**Environment:** Database  
**Type of threat:** Hashing  
**Explanation:** It is possible to break encryptions if the algorithm to be used is weak. It could be obtained with a dictionary and / or doing reverse engineering to the same algorithm.
