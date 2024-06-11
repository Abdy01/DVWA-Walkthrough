# Content Security Policy - Bypass

## About
> Content Security Policy (CSP) is used to define where scripts and other resources can be loaded or executed from. This module will walk you through ways to bypass the policy based on common mistakes made by developers.
> 
> None of the vulnerabilities are actual vulnerabilities in CSP, they are vulnerabilities in the way it has been implemented.

Source: DVWA Documentation

## Low Security
The objective of this challenge is to bypass Content Security Policy (CSP) and execute JavaScript in the page.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp1.png?raw=true">
</p>

The URLs contain the following:

https://digi.ninja/dvwa/alert.js
- alert("CSP Bypassed");

https://digi.ninja/dvwa/alert.txt
- alert("CSP Bypassed");

https://digi.ninja/dvwa/cookie.js
- alert(document.cookie);

https://digi.ninja/dvwa/forced_download.js
- alert ("This should download and not execute");

https://digi.ninja/dvwa/wrong_content_type.js
- alert ("This should not execute");

We have the following CSP header set:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp2.png?raw=true">
</p>

Scripts are allowed to be loaded from self + several domains.<br/>
If we add the first payload, the alert box is triggered. Some of them are working, some of them are not.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp3.png?raw=true">
</p>

Feel free to try them and check whichever work. You can follow `Network` tab from Developer Tools to verify if the CSP header blocked the script or not.<br/>
Details about the behaviour can be found in the Help menu of DVWA application.

## Medium Security
"The CSP policy tries to use a nonce to prevent inline scripts from being added by attackers."

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp4.png?raw=true">
</p>

An inline script such as:`<script>alert(1)</script>`, indeed doesn't work.<br/>
A CSP nonce is a randomly generated value included in the header and in the nonce attribute of inline `<script>` and `<style>` tags. It allows these specific scripts or styles to be executed while blocking all others, enhancing protection against cross-site scripting (XSS) attacks.<br/>
Looking at the header, we can see the following:<br/>
`Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';`<br/>
The `unsafe-inline` is used to allow inline scripts.

Please check: https://content-security-policy.com/unsafe-inline/ for more details.

Using the nonce in our script, we can successfully execute:`<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">alert(1)</script>`.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp5.png?raw=true">
</p>

Besides the usage of `unsafe-inline`, the nonce is also a non-random string.

## High Security
In this scenario the page makes a JSONP call to source/jsonp.php passing the name of the function to callback.<br/>

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp6.png?raw=true">
</p>

The request:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp7.png?raw=true">
</p>

Source code high.php:
```php
<?php
$headerCSP = "Content-Security-Policy: script-src 'self';";

header($headerCSP);

?>
<?php
if (isset ($_POST['include'])) {
$page[ 'body' ] .= "
    " . $_POST['include'] . "
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
    <p>The page makes a call to ' . DVWA_WEB_PAGE_TO_ROOT . '/vulnerabilities/csp/source/jsonp.php to load some code. Modify that page to run your own code.</p>
    <p>1+2+3+4+5=<span id="answer"></span></p>
    <input type="button" id="solve" value="Solve the sum" />
</form>

<script src="source/high.js"></script>
';
```

Source code high.js:
```js
function clickButton() {
    var s = document.createElement("script");
    s.src = "source/jsonp.php?callback=solveSum";
    document.body.appendChild(s);
}

function solveSum(obj) {
    if ("answer" in obj) {
        document.getElementById("answer").innerHTML = obj['answer'];
    }
}

var solve_button = document.getElementById ("solve");

if (solve_button) {
    solve_button.addEventListener("click", function() {
        clickButton();
    });
}
```

The JavaScript on the page will execute whatever is returned by the page, so let's add an alert box instead of the solveSum function in the Response.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp8.png?raw=true">
</p>

The alert is executed!<br/>
Taking a look at the request we find `jsonp.php?callback=solveSum`. So, let's try: `jsonp.php?callback=alert(1)`.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp9.png?raw=true">
</p>

The code is executed again!

## Impossible Security
Unlike the high level, this does a JSONP call but does not use a callback, instead it hardcodes the function to call.<br/>
Furthermore, the CSP is also set on self only.

Source code:
```php
function clickButton() {
    var s = document.createElement("script");
    s.src = "source/jsonp_impossible.php";
    document.body.appendChild(s);
}
```

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp10.png?raw=true">
</p>

The request:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/CSP-Bypass/!images/csp11.png?raw=true">
</p>

The CSP-Bypass challenge was also new for me, so please do more research if something is not clear.