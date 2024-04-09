# SQL Injection
## Low Security

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql1.png?raw=true">
</p>

Inserting `1'` will return a 500 Internal Server Error.

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
```

We can see that the `'$id'` is not verified, so we can inject the following: `1' OR 1=1;#`

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql2.png?raw=true">
</p>

With this payload we bypass the query using the quote symbol and add the logic operator OR, which will make the query to choose between the id given or a true statement such as 1=1.
The pound sign (#) is used to comment the rest of the query.

## Medium Security

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql3.png?raw=true">
</p>

For the Medium security level we can not change the value of the parameter directly from the UI, but we can use a Proxy tool like Burp Suite to modify the HTTP request.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql4.png?raw=true">
</p>

We will add the payload without the quote because now the $id is treated as integer. Then we URL encode the payload and send it.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/SQL-Injection/!images/sql5.png?raw=true">
</p>

Source code:
```php
$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

// Get results
while( $row = mysqli_fetch_assoc( $result ) ) {
    // Display values
    $first = $row["first_name"];
    $last  = $row["last_name"];

    // Feedback for end user
    echo "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
```