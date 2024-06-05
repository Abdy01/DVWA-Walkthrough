# Weak Session IDs

## About
> Knowledge of a session ID is often the only thing required to access a site as a specific user after they have logged in.
> 
> If that session ID is able to be calculated or easily guessed, then an attacker will have an easy way to gain access to user accounts without having to brute force passwords or find other vulnerabilities such as Cross-Site Scripting.

Source: DVWA Documentation

## Low Security
"This module uses four different ways to set the dvwaSession cookie value, the objective of each level is to work out how the ID is generated and then infer the IDs of other system users."

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Weak-Session-IDs/!images/ws1.png?raw=true">
</p>

To solve Weak Session IDs, we will see if we can guess how are the cookies generated.<br/>
For the Low level, the method is very simple, the request looks like this:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Weak-Session-IDs/!images/ws2.png?raw=true">
</p>

We can see in the response `Set-Cookie: dvwaSession=2`.<br/>
The next values are: 3,4,5... , so the cookie is incremented with 1 each time.

Source code:
```php
<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    if (!isset ($_SESSION['last_session_id'])) {
        $_SESSION['last_session_id'] = 0;
    }
    $_SESSION['last_session_id']++;
    $cookie_value = $_SESSION['last_session_id'];
    setcookie("dvwaSession", $cookie_value);
}
?> 
```
To understand the impact of this vulnerability, let's say we have a cookie `role=user`.<br/>
We can modify it as `role=admin` to get access to more functionalities.<br/>

Another example, we have `dvwaSession=83`.<br/>
Changing this value to `dvwaSession=1`, as the first user from the database, could give us administrator rights.<br/>
In this laboratory we will focus only on the generation process.

## Medium Security
For Medium level we have the following values:
```
dvwaSession=1717621254
dvwaSession=1717621267
dvwaSession=1717621280
```
As you may have already guessed, these values are generated using time() function.<br/>
To check the value in real-time: https://www.epochconverter.com/

Source code:
```php
<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $cookie_value = time();
    setcookie("dvwaSession", $cookie_value);
}
?> 
```

## High Security
For High level we have the following values:
```
Set-Cookie: dvwaSession=c4ca4238a0b923820dcc509a6f75849b; expires=Wed, 05 Jun 2024 22:01:55 GMT; Max-Age=3600; path=/vulnerabilities/weak_id/; domain=localhost
Set-Cookie: dvwaSession=c81e728d9d4c2f636f067f89cc14862c; expires=Wed, 05 Jun 2024 22:01:57 GMT; Max-Age=3600; path=/vulnerabilities/weak_id/; domain=localhost
Set-Cookie: dvwaSession=eccbc87e4b5ce2fe28308fd9f2a7baf3; expires=Wed, 05 Jun 2024 22:02:00 GMT; Max-Age=3600; path=/vulnerabilities/weak_id/; domain=localhost
```
First we can see that we have other values set. The cookie is restricted to the domain and path specified and has also an expiration time.<br/>
Now, looking at the value we noted that is a hash format. Let's try to crack them using: https://crackstation.net/ <br/>
We will find that the values are: 1,2,3. So, the method is the same as the Low level, but now the values are md5 encrypted.

Source code:
```php
<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    if (!isset ($_SESSION['last_session_id_high'])) {
        $_SESSION['last_session_id_high'] = 0;
    }
    $_SESSION['last_session_id_high']++;
    $cookie_value = md5($_SESSION['last_session_id_high']);
    setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false);
}

?> 
```

## Impossible Security
For Impossible level we have the following values:
```
Set-Cookie: dvwaSession=c3b4e098b5b95ec80ae89f3b420e67418ec8769c; expires=Wed, 05 Jun 2024 22:08:40 GMT; Max-Age=3600; path=/vulnerabilities/weak_id/; domain=localhost; secure; HttpOnly
Set-Cookie: dvwaSession=d16c6e12dba74435b3363d13aa04ab82adf9ee07; expires=Wed, 05 Jun 2024 22:08:48 GMT; Max-Age=3600; path=/vulnerabilities/weak_id/; domain=localhost; secure; HttpOnly
Set-Cookie: dvwaSession=409a639818cc2a4db33b4723f2d4cfdf7bc7fa60; expires=Wed, 05 Jun 2024 22:08:49 GMT; Max-Age=3600; path=/vulnerabilities/weak_id/; domain=localhost; secure; HttpOnly
```

Source code:
```php
<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $cookie_value = sha1(mt_rand() . time() . "Impossible");
    setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], true, true);
}
?> 
```
The hash is used now on mt_rand() function which is generating a random integer such as `305261626`.<br/>
In this case the session cookie is impossible to guess.<br/>
Furthermore, the secure and httponly flags were activated.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Weak-Session-IDs/!images/ws3.png?raw=true">
</p>

Secure flag ensures that the cookie is only sent over secure HTTPS connections, protecting the cookie from being transmitted over insecure networks and reducing the risk of man-in-the-middle attacks.<br/>
HttpOnly flag prevents the cookie from being accessed by client-side scripts (JavaScript), enhancing security by mitigating the risk of cross-site scripting (XSS) attacks.