# CSRF

## About
> CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they are currently authenticated. With a little help of social engineering (such as sending a link via email/chat), an attacker may force the users of a web application to execute actions of the attacker's choosing.
> 
> A successful CSRF exploit can compromise end user data and operation in case of normal user. If the targeted end user is the administrator account, this can compromise the entire web application.
> 
> This attack may also be called "XSRF", similar to "Cross Site Scripting (XSS)", and they are often used together.

Source: DVWA Documentation

## Low Security
The functionality of this exercise is a change password input and the objective of the challenge is to make the current user change their own password, without them knowing about their actions, using a CSRF attack.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf1.png?raw=true">
</p>

We also have a Test Credentials button which will send us to other window where we can test the current credentials.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf2.png?raw=true">
</p>

After changing the password, the URL will look like this:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf3.png?raw=true">
</p>

Of course is bad using the password in plaintext as parameter, but just looking at the URL, we can ask what would happen if someone visit such a URL? Let's try it out!<br/>
For example we craft the following URL: `http://localhost/DVWA/vulnerabilities/csrf/?password_new=password123&password_conf=password123&Change=Change#` and send it to someone.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf4.png?raw=true">
</p>

When the victim visits this URL, the action of changing their password is automatically done. The victim needs to be already logged-in to the web application and the change password request will be done without their consent.

## Medium Security

## High Security

## Impossible Security