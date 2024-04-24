# XSS (DOM)

## About
> "Cross-Site Scripting (XSS)" attacks are a type of injection problem, in which malicious scripts are injected into the otherwise benign and trusted web sites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application using input from a user in the output, without validating or encoding it.
> 
> An attacker can use XSS to send a malicious script to an unsuspecting user. The end user's browser has no way to know that the script should not be trusted, and will execute the JavaScript. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by your browser and used with that site. These scripts can even rewrite the content of the HTML page.
> 
> DOM Based XSS is a special case of reflected where the JavaScript is hidden in the URL and pulled out by JavaScript in the page while it is rendering rather than being embedded in the page when it is served. This can make it stealthier than other attacks and WAFs or other protections which are reading the page body do not see any malicious content.

Source: DVWA Documentation

## Low Security
I recommend to check first XSS(Reflected) and XSS(Stored).<br/>
In this exercise we have a drop-down language selector.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(DOM)/!images/xssd1.png?raw=true">
</p>

The item selected is also reflected in the URL, so we can edit it from there.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(DOM)/!images/xssd2.png?raw=true">
</p>

The difference here, in DOM XSS, is that the input is not reflected in the source code, but it is reflected in HTML DOM.<br/>
I really recommend this article to better understand DOM XSS: https://ethicalhacs.com/dvwa-dom-xss-exploit/ .

Source code:
```php
<?php
# No protections, anything goes
?> 
```
The objective of the challenge is to steal the cookie of a logged in user. Similar solutions are already presented in XSS Reflected section.

## Medium Security
For Medium level we have the following source code:
```php
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
    $default = $_GET['default'];
    
    # Do not allow script tags
    if (stripos ($default, "<script") !== false) {
        header ("location: ?default=English");
        exit;
    }
}

?> 
```
We can see that if our payload contains `<script`, then the value of the parameter will be set to `English`.<br/>
But we can use other payloads, as we did for the other XSS challenges.<br/>
Using the next payload: `?default=English<img src=x onerror=alert(document.domain)>` is not really working because the image can not be added in the drop-down.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(DOM)/!images/xssd3.png?raw=true">
</p>

Looking at the code we can see that the values are using `<option>` tag, so let's close the entire `<select>` tag.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(DOM)/!images/xssd4.png?raw=true">
</p>

## High Security
Source code:
```php
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {

    # White list the allowable languages
    switch ($_GET['default']) {
        case "French":
        case "English":
        case "German":
        case "Spanish":
            # ok
            break;
        default:
            header ("location: ?default=English");
            exit;
    }
}

?> 
```
This is a tricky one because now only the languages from the switch are available.<br/>
The help section is saying that: `The developer is now white listing only the allowed languages, you must find a way to run your code without it going to the server.`.<br/>
There is a technique that can be used to exploit this vulnerability. Using the `#` symbol in the URL will make all text after the `#` to not be sent to the server. Using this technique we will add the payload in the URL, but this will not be sent further.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(DOM)/!images/xssd5.png?raw=true">
</p>

The payload used: `?default=#English<script>alert(1)</script>`.

Another method which I discovered later, is to use the `&` (AND) operator like this: `?default=English&<script>alert(1)</script>`. In this case, the English value will be treated as true and the second group is still accepted because the condition is that one of them to be true.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(DOM)/!images/xssd6.png?raw=true">
</p>

## Impossible Security
The Impossible level does not actually use any implementations in the back-end, because the content of the URL is encoded by default by most of the browsers in client side.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(DOM)/!images/xssd7.png?raw=true">
</p>