# File Inclusion

## About
```
Some web applications allow the user to specify input that is used directly into file streams or allows the user to upload files to the server.
At a later time the web application accesses the user supplied input in the web applications context. By doing this, the web application is allowing the potential for malicious file execution.
If the file chosen to be included is local on the target machine, it is called "Local File Inclusion (LFI). But files may also be included on other machines, which then the attack is a "Remote File Inclusion (RFI).
When RFI is not an option. using another vulnerability with LFI (such as file upload and directory traversal) can often achieve the same effect.

Note, the term "file inclusion" is not the same as "arbitrary file access" or "file disclosure".
```
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

For example this payload: `http://localhost/DVWA/vulnerabilities/fi/?page=../../../../../../../../etc/passwd` is using many `../`, because we want to access the `/etc/passwd` from the root path `/`. So we add many `../` to be sure that we arrived at the root path.

## File Inclusion vs Directory Traversal

## Medium Security

## High Security

## Impossible Security
