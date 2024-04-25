# XSS (Stored)

## About
> "Cross-Site Scripting (XSS)" attacks are a type of injection problem, in which malicious scripts are injected into the otherwise benign and trusted web sites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application using input from a user in the output, without validating or encoding it.
> 
> An attacker can use XSS to send a malicious script to an unsuspecting user. The end user's browser has no way to know that the script should not be trusted, and will execute the JavaScript. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other sensitive information retained by your browser and used with that site. These scripts can even rewrite the content of the HTML page.
> 
> The XSS is stored in the database. The XSS is permanent, until the database is reset or the payload is manually deleted.

Source: DVWA Documentation

## Low Security
I recommend first to read the XSS (Reflected) challenge to better understand this one.<br/>
For this challenge we have a form where we can add comments on the page:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Stored)/!images/xsss1.png?raw=true">
</p>

In XSS Stored vulnerability the payload is stored on the server, therefore the comments posted by `test` and `Hacker` can be seen by any user logged in to DVWA application.<br/>
The impact is bigger than XSS Reflected. There the users need to click an URL, but here if the payload is injected in the page, anyone who visits it will be affected by the XSS.<br/>

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Stored)/!images/xsss2.png?raw=true">
</p>

In the image above, we added a malicious payload containing javascript code, and now this is stored on the page. We can login with other user and visit the page to check that the alert would still pop up.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Stored)/!images/xsss3.png?raw=true">
</p>

Source code:
```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );

    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Sanitize name input
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    //mysql_close();
}

?> 
```
The objective of the challenge is to redirect everyone to a web page of your choosing.<br/>
We can use the following payload:`'<img src=x onerror="window.location.href='https://google.com'">`.<br/>
We have maximum length set on `Name` and `Message` fields, but this is only in front-end. We can modify the code with `Inspect Element` option, or modify the request using a Proxy.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Stored)/!images/xsss4.png?raw=true">
</p>

If we are using Proxy, the payload also needs to be URL-encoded.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Stored)/!images/xsss5.png?raw=true">
</p>

Now everyone who access XSS(Stored) endpoint will be redirected to google.com.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/XSS(Stored)/!images/xsss6.png?raw=true">
</p>

## Medium Security
Source code:
```php
// Sanitize message input
$message = htmlspecialchars( $message );

// Sanitize name input
$name = str_replace( '<script>', '', $name ); 
```
The `Message` is now filtered, but keep in mind that every input could be vulnerable. In this case the injection is changed to the `Name` field.

## Medium-High-Impossible Security
The implementations are the same as for XSS (Reflected), so please visit the solutions there.