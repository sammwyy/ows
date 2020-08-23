# OWS
The online-with-security project is a small cyber security manuscript for the prevention of computer attacks.

## Introduction
Computer hackers in most cases are due to bad practices when programming a system that will be available to any user via the internet.  
  
In this guide we will see a summary of the most common problems in terms of web security and how to solve them.  
  
This guide will not ensure that your service is 100% inpenetrable but it will greatly decrease the possibilities and as long as there are no human errors then there would be no need to worry and remember not only to look at the security of what your programs but also what you use. (libraries, frameworks, technologies)  

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

### Error Messages Information Exposure
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** Disclosure  
**Explanation:** Informational error messages are messages that the server returns when an unhandled exception occurs or a handled exception that displays its message on the screen. This is usually because you are working in a development environment and not a production environment.

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


### Sensitive Case Database
**Danger level:** Low  
**Environment:** Database  
**Type of threat:** Spoofing  
**Explanation:** There are cases where we forget that the default databases are sensitive, that is to say that if we store something in lowercase we cannot obtain it with a query being in uppercase and vice versa. A case of insecure application would be when the user "john" is registered and when trying to register again the user "john" it says that it is already in the database but when registering "jOhn" (using capital letters) it does allow us doing it.

### System Properties Disclosure
**Danger level:** Low  
**Environment:** System & Software  
**Type of threat:** Disclosure  
**Explanation:** This exploit is due to the fact that an application or software is exposing system data such as the same software and version that are being used, operating system or hardware components.

### Unrestricted File Upload
**Danger level:** Low  
**Environment:** HTTP  
**Type of threat:** Multiples  
**Explanation:** If we do not control the upload of files to the server, we can make the mistake of allowing the upload of a script that is executed server-side, an asset that is executed client-side or application errors or libraries such as buffer-overflow, arbitrary code execution, cross site scripting, hijacking, vulnerable antivirus software, malware flaw exploit, FsDOS or change the path where the file will be saved by modifying its metadata or replacing a vital file on the system where it will be saved.

### Weak Encryption Strength
**Danger level:** Low  
**Environment:** Database  
**Type of threat:** Hashing  
**Explanation:** It is possible to break encryptions if the algorithm to be used is weak. It could be obtained with a dictionary and / or doing reverse engineering to the same algorithm.
