# Damn Vulnerable Web Application - DVWA
## Walktrough

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/!images/logo.png?raw=true">
</p>


> Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable.<br/>
> It's main goal is to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and to aid both students & teachers to learn about web application security in a controlled class room environment.<br/>
> The aim of DVWA is to practice some of the most common web vulnerabilities, with various levels of difficultly, with a simple straightforward interface.<br/>

Source: DVWA Documentation

## Important!
My goal is to make you to understand how each vulnerability works. This application is not created by me and all rights belong to digininja.
If you want to know more about the application or to follow the installation steps, I invite you to check: https://github.com/digininja/DVWA .

The attacks presented are intended for educational purposes only. Unauthorized use of these attacks on web applications without explicit permission is illegal and unethical. Use responsibly and with proper authorization.

I know there are multiple articles regarding DVWA challenges, but I wanted to create a full walkthrough based on my own experience, and to explain a little more than is necessary.<br/>
I encourage you to check other available walkthroughs, because you will find different perspectives on how to solve challenges.<br/>
I want to mentione 2 walkthroughs from which I was inspired:
- CryptoCat DVWA playlist on Youtube.
- https://github.com/keewenaw/dvwa-guide-2019/blob/master/

## Overview
<p align="left">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/!images/login.png?raw=true">
</p>

First time you have to login with the default credentials admin:password, then you will have access at the main page.

<p align="left">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/!images/Main.png?raw=true">
</p>

On the main page you can find some information about application and on the left side you will see a list of buttons with the vulnerabilities.<br/>
First time you have to set the security of the application.<br/>
Another setting that you can make is to reset the database, in case you mess around with the application.

## Security
On the Application you can find four levels of Security:
- Low
- Medium
- High
- Impossible

Is important to take each step of security and check the source code to see how the code should be implemented to be secured.

<p align="left">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/!images/Security.png?raw=true">
</p>