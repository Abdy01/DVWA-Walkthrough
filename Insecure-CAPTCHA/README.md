# Insecure Captcha

## About
> A CAPTCHA is a program that can tell whether its user is a human or a computer. You've probably seen them - colourful images with distorted text at the bottom of Web registration forms. CAPTCHAs are used by many websites to prevent abuse from "bots", or automated programs usually written to generate spam. No computer program can read distorted text as well as humans can, so bots cannot navigate sites protected by CAPTCHAs.
> 
> CAPTCHAs are often used to protect sensitive functionality from automated bots. Such functionality typically includes user registration and changes, password changes, and posting content. In this example, the CAPTCHA is guarding the change password functionality for the user account. This provides limited protection from CSRF attacks as well as automated bot guessing.

Source: DVWA Documentation

## Low Security
For this challenge you have to register for a reCAPTCHA API key with a gmail account, then to add the keys in config.inc.php.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic1.png?raw=true">
</p>

We have a captcha that must be done in order to change our password, and the objective is to bypass it.<br/>
After the captcha is done, in the next screen is another confirmation button:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic2.png?raw=true">
</p>

Then a confirmation message that the password was changed.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic3.png?raw=true">
</p>

Let's take a look also on the HTTP requests:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic4.png?raw=true">
</p>

And the request from the second window with the confirmation button:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic5.png?raw=true">
</p>

What if we try to send again the second request?

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic6.png?raw=true">
</p>

The password is changed without the verification of the captcha.<br/>
"The developer has made the assumption that all users will progress through screen 1, complete the CAPTCHA, and then move on to the next screen where the password is actually updated.<br/>
By submitting the new password directly to the change page, the user may bypass the CAPTCHA system."<br/>

The current password can be checked with CSRF - Test Credentials option.

Source code:
```php
<?php

if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '1' ) ) {
    // Hide the CAPTCHA form
    $hide_form = true;

    // Get input
    $pass_new  = $_POST[ 'password_new' ];
    $pass_conf = $_POST[ 'password_conf' ];

    // Check CAPTCHA from 3rd party
    $resp = recaptcha_check_answer(
        $_DVWA[ 'recaptcha_private_key'],
        $_POST['g-recaptcha-response']
    );

    // Did the CAPTCHA fail?
    if( !$resp ) {
        // What happens when the CAPTCHA was entered incorrectly
        $html     .= "<pre><br />The CAPTCHA was incorrect. Please try again.</pre>";
        $hide_form = false;
        return;
    }
    else {
        // CAPTCHA was correct. Do both new passwords match?
        if( $pass_new == $pass_conf ) {
            // Show next stage for the user
            echo "
                <pre><br />You passed the CAPTCHA! Click the button to confirm your changes.<br /></pre>
                <form action=\"#\" method=\"POST\">
                    <input type=\"hidden\" name=\"step\" value=\"2\" />
                    <input type=\"hidden\" name=\"password_new\" value=\"{$pass_new}\" />
                    <input type=\"hidden\" name=\"password_conf\" value=\"{$pass_conf}\" />
                    <input type=\"submit\" name=\"Change\" value=\"Change\" />
                </form>";
        }
        else {
            // Both new passwords do not match.
            $html     .= "<pre>Both passwords must match.</pre>";
            $hide_form = false;
        }
    }
}

if( isset( $_POST[ 'Change' ] ) && ( $_POST[ 'step' ] == '2' ) ) {
    // Hide the CAPTCHA form
    $hide_form = true;

    // Get input
    $pass_new  = $_POST[ 'password_new' ];
    $pass_conf = $_POST[ 'password_conf' ];

    // Check to see if both password match
    if( $pass_new == $pass_conf ) {
        // They do!
        $pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
        $pass_new = md5( $pass_new );

        // Update database
        $insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . dvwaCurrentUser() . "';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

        // Feedback for the end user
        echo "<pre>Password Changed.</pre>";
    }
    else {
        // Issue with the passwords matching
        echo "<pre>Passwords did not match.</pre>";
        $hide_form = false;
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?> 
```

## Medium Security
The Medium level has only implemented a state variable to confirm that the captcha was successfully completed in the first place.<br/>
Because the variable is in the client-side, this can be easly manipulated by the user.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic7.png?raw=true">
</p>

## High Security
For the High level, the code seems to look secure, however, the developers left some important test values in the production code.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic8.png?raw=true">
</p>

These values work as an alternative way for the captcha process. If we try a request with these values:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic9.png?raw=true">
</p>

It worked!

## Impossible Security
For the Impossible level, the developers fixed all previous security issues.<br/>
The process has been simplified so that data and captcha verification occurs in one single step.<br/>
The state variable was moved server side, so the user cannot alter it.<br/>
Also, the password can no longer be changed without knowing the current password.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Insecure-CAPTCHA/!images/ic10.png?raw=true">
</p>
