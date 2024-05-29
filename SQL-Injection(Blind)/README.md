# SQL Injection Blind

## About
> When an attacker executes SQL injection attacks, sometimes the server responds with error messages from the database server complaining that the SQL query's syntax is incorrect.
> Blind SQL injection is identical to normal SQL Injection except that when an attacker attempts to exploit an application, rather then getting a useful error message, they get a generic page specified by the developer instead. This makes exploiting a potential SQL Injection attack more difficult but not impossible.
> An attacker can still steal data by asking a series of True and False questions through SQL statements, and monitoring how the web application response (valid entry retunred or 404 header set).
>
> "Time based" injection method is often used when there is no visible feedback in how the page different in its response (hence its a blind attack).
> This means the attacker will wait to see how long the page takes to response back. If it takes longer than normal, their query was successful.

Source: DVWA Documentation

## Low Security
The functionality is almost the same as the previous challenge (SQL Injection). We have an ID input and we can verify if the user with that ID exist or not.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection(Blind)/!images/sqlib1.png?raw=true">
</p>

The application will not return user's information anymore, only the confirmation that the user with that ID exists in the database or not.<br/>
The same payload used to return all users from the database will not work in this case.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection(Blind)/!images/sqlib2.png?raw=true">
</p>

Even if the payload seems that is not working, this is not the case. We received a True response because we compared `2` which will return True, with the True statement:`1=1`.<br/>
So in this case a True OR True value will return True.

For example `2' AND 1=1;#` will return True, but `2' AND 1=2;#` will return False, because for AND operator both items must be True to return True.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection(Blind)/!images/sqlib3.png?raw=true">
</p>

With this we confirmed the presence of SQL Blind Injection.

To better understand this concept, please take a look at `Boolean Logical Operators`.
https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/operators/boolean-logical-operators

We can also test the vulnerability using sleep() commands. We can say `2' AND sleep(3);#` and if the injection is successful the response will come after 3 seconds.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection(Blind)/!images/sqlib4.png?raw=true">
</p>

The objective of the challenge is to find the version of the SQL database software through a blind SQL attack.<br/>
Using the following payload we can start enumerate the version one by one: `2' AND substring(version(),1,1)=1;#`.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection(Blind)/!images/sqlib5.png?raw=true">
</p>

We can see that the version starts with `10.`. If you already completed SQL Injection part, you know that the version in my case is `10.11.6-MariaDB-2`.<br/>
Of course the process is not simple and requires a lot of time. For exploitations like this, automation is the key.<br/>
You can create your own scripts or use known tools.<br/>

Source code:
```php
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
    // Get input
    $id = $_GET[ 'id' ];
    $exists = false;

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            // Check database
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            try {
                $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ); // Removed 'or die' to suppress mysql errors
            } catch (Exception $e) {
                print "There was an error.";
                exit;
            }

            $exists = false;
            if ($result !== false) {
                try {
                    $exists = (mysqli_num_rows( $result ) > 0);
                } catch(Exception $e) {
                    $exists = false;
                }
            }
            ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
            break;
        case SQLITE:
            global $sqlite_db_connection;

            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
            try {
                $results = $sqlite_db_connection->query($query);
                $row = $results->fetchArray();
                $exists = $row !== false;
            } catch(Exception $e) {
                $exists = false;
            }

            break;
    }

    if ($exists) {
        // Feedback for end user
        echo '<pre>User ID exists in the database.</pre>';
    } else {
        // User wasn't found, so the page wasn't!
        header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

        // Feedback for end user
        echo '<pre>User ID is MISSING from the database.</pre>';
    }
}
?>
```
## Medium-High-Impossible Security
The implementations are the same as for SQL Injection, so please visit the solutions there.