# Open HTTP Redirect

## About
> OWASP define this as:
>
> Unvalidated redirects and forwards are possible when a web application accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. By modifying untrusted URL input to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials. 
> 
> As suggested above, a common use for this is to create a URL which initially goes to the real site but then redirects the victim off to a site controlled by the attacker. This site could be a clone of the target's login page to steal credentials, a request for credit card details to pay for a service on the target site, or simply a spam page full of advertising.

Source: DVWA Documentation

## Low Security
In this challenge we have 2 buttons that send us to some quotes.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Open-HTTP-Redirect/!images/or1.png?raw=true">
</p>

We have the quote and a Back button.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Open-HTTP-Redirect/!images/or2.png?raw=true">
</p>

The main URL looks like this: http://localhost/DVWA/vulnerabilities/open_redirect/ <br/>
And the one from the second image looks like this: http://localhost/DVWA/vulnerabilities/open_redirect/source/info.php?id=1 <br/>
Now, if we take a look at the URL before clicking the first quote, we will find the next one:<br/>
http://localhost/DVWA/vulnerabilities/open_redirect/source/low.php?redirect=info.php?id=1
This can be also noted by checking the requests:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Open-HTTP-Redirect/!images/or3.png?raw=true">
</p>

The redirect parameter is used to redirect us to info.php file from /source/. Just adding other destination, the redirection will be changed to the new one.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Open-HTTP-Redirect/!images/or4.png?raw=true">
</p>

To understand the severity, the victim receives a URL from a legitimate application and when an action is performed the user is redirected to other sources. In this case, the user only needs to access the URL and will be immediately redirected.<br/>
Is important to always be careful at the URL visited.<br/>

Source code:
```php
<?php

if (array_key_exists ("redirect", $_GET) && $_GET['redirect'] != "") {
    header ("location: " . $_GET['redirect']);
    exit;
}

http_response_code (500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?> 
```

## Medium Security
Source code:
```php
<?php

if (array_key_exists ("redirect", $_GET) && $_GET['redirect'] != "") {
    if (preg_match ("/http:\/\/|https:\/\//i", $_GET['redirect'])) {
        http_response_code (500);
        ?>
        <p>Absolute URLs not allowed.</p>
        <?php
        exit;
    } else {
        header ("location: " . $_GET['redirect']);
        exit;
    }
}

http_response_code (500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?> 
```

Now we are not able to use anything starting with `http://` or `https://`.<br/>
To solve this problem, we can use Protocol-relative URL: https://en.wikipedia.org/wiki/Wikipedia:Protocol-relative_URL <br/>
Using the following payload, the user will be redirected again as we want:<br/>
http://localhost/DVWA/vulnerabilities/open_redirect/source/medium.php?redirect=//google.com

## High Security
Source code:
```php
<?php

if (array_key_exists ("redirect", $_GET) && $_GET['redirect'] != "") {
    if (strpos($_GET['redirect'], "info.php") !== false) {
        header ("location: " . $_GET['redirect']);
        exit;
    } else {
        http_response_code (500);
        ?>
        <p>You can only redirect to the info page.</p>
        <?php
        exit;
    }
}

http_response_code (500);
?>
<p>Missing redirect target.</p>
<?php
exit;
?> 
```

For this challenge we can see that the application is looking for `info.php` string.<br/>
The application is not looking only for `info.php`, instead the target should contain this string.<br/>
In this case we can bypass it using:<br/>
http://localhost/DVWA/vulnerabilities/open_redirect/source/high.php?redirect=//google.com/info.php <br/>
An attacker can use an endpoint like `info.php` to host a malicious script on it. Therefore, this is not a good security measure.

## Impossible Security
"Rather than accepting a page or URL as the redirect target, the system uses ID values to tell the redirect page where to redirect to.<br/>
This ties the system down to only redirect to pages it knows about and so there is no way for an attacker to modify things to go to a page of their choosing."

URL: http://localhost/DVWA/vulnerabilities/open_redirect/source/impossible.php?redirect=1

Source code:
```php
<?php

$target = "";

if (array_key_exists ("redirect", $_GET) && is_numeric($_GET['redirect'])) {
    switch (intval ($_GET['redirect'])) {
        case 1:
            $target = "info.php?id=1";
            break;
        case 2:
            $target = "info.php?id=2";
            break;
        case 99:
            $target = "https://digi.ninja";
            break;
    }
    if ($target != "") {
        header ("location: " . $target);
        exit;
    } else {
        ?>
        Unknown redirect target.
        <?php
        exit;
    }
}

?>
Missing redirect target. 
```