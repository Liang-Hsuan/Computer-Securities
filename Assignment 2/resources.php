<?php

/******************************************************************************
 * This file contains the server side PHP code that students need to modify
 * to implement the password safe application.  Another PHP file, server.php,
 * should not need to be modified and handles initialization of some variables,
 * resource arbitration, and outputs the reponse.  The last PHP file is api.php
 * which should also not be modified by students and which provides an API
 * for resource functions to communicate with clients.
 *
 * Student code in this file should only interact with the outside world via
 * the parameters to the functions.  These parameters are the same for each
 * function.  The Request and Reponse classes can be found in api.php.
 * For more information on PDO database connections, see the documentation at
 * https://www.php.net/manual/en/book.pdo.php or other websites.
 *
 * The parameters to each function are:
 *   -- $request A Request object, passed by reference (see api.php)
 *   -- $response A Response object, passed by reference (see api.php)
 *   -- $db A PDO database connection, passed by reference
 *
 * The functions must also return the same values.  They are:
 *   -- true on success, false on failure
 *
 * Students should understand how to use the Request and Response objects, so
 * please spend some time looking at the code in api.php.  Apart from those
 * classes, the only other API function that students should use is the
 * log_to_console function, which MUST be used for server-side logging.
 *
 * The functions that need to be implemented all handle a specific type of
 * request from the client.  These map to the resources the client JavaScript
 * will call when the user performs certain actions.
 * The functions are:
 *    - preflight -- This is a special function in that it is called both
 *                   as a separate "preflight" resource and it is also called
 *                   before every other resource to perform any preflight
 *                   checks and insert any preflight response.  It is
 *                   especially important that preflight returns true if the
 *                   request succeeds and false if something is wrong.
 *                   See server.php to see how preflight is called.
 *    - signup -- This resource should create a new account for the user
 *                if there are no problems with the request.
 *    - identify -- This resource identifies a user and returns any
 *                  information that the client would need to log in.  You
 *                  should be especially careful not to leak any information
 *                  through this resource.
 *    - login -- This resource checks user credentials and, if they are valid,
 *               creates a new session.
 *    - sites -- This resource should return a list of sites that are saved
 *               for a logged in user.  This result is used to populate the
 *               dropdown select elements in the user interface.
 *    - save -- This resource saves a new (or replaces an existing) entry in
 *              the password safe for a logged in user.
 *    - load -- This resource loads an existing entry from the password safe
 *              for a logged in user.
 *    - logout -- This resource should destroy the existing user session.
 *
 * It is VERY important that resources set appropriate HTTP response codes!
 * If a resource returns a 5xx code (which is the default and also what PHP
 * will set if there is an error executing the script) then I will assume
 * there is a bug in the program during grading.  Similarly, if a resource
 * returns a 2xx code when it should fail, or a 4xx code when it should
 * succeed, then I will assume it has done the wrong thing.
 *
 * You should not worry about the database getting full of old entries, so
 * don't feel the need to delete expired or invalid entries at any point.
 *
 * The database connection is to the sqlite3 database "passwordsafe.db".
 * The commands to create this database (and therefore its schema) can
 * be found in "initdb.sql".  You should familiarize yourself with this
 * schema.  Not every table or field must be used, but there are many
 * helpful hints contained therein.
 * The database can be accessed to run queries on it with the command:
 *    sqlite3 passwordsafe.db
 * It is also easy to run SQL scripts on it by sending them to STDIN.
 *    sqlite3 passwordsafe.db < myscript.sql
 * This database can be recreated (to clean it up) by running:
 *    sqlite3 passwordsafe.db < dropdb.sql
 *    sqlite3 passwordsafe.db < initdb.sql
 *
 * This is outlined in more detail in api.php, but the Response object
 * has a few methods you will need to use:
 *    - set_http_code -- sets the HTTP response code (an integer)
 *    - success       -- sets a success status message
 *    - failure       -- sets a failure status message
 *    - set_data      -- returns arbitrary data to the client (in json)
 *    - set_cookie    -- sets an HTTP-only cookie on the client that
 *                       will automatically be returned with every
 *                       subsequent request.
 *    - delete_cookie -- tells the client to delete a cookie.
 *    - set_token     -- passes a token (via data, not headers) to the
 *                       client that will automatically be returned with
 *                       every subsequent request.
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * To get the current date and time in a format the database expects:
 *      $now = new DateTime();
 *      $now->format(DateTimeInterface::ISO8601);
 *
 * To get a date and time 15 minutes in the future (for the database):
 *      $now = new DateTime();
 *      $interval = new DateInterval("PT15M");
 *      $now->add($interval)->format(DateTimeInterface::ISO8601);
 *
 * Notice that, like JavaScript, PHP is loosely typed.  A common paradigm in
 * PHP is for a function to return some data on success or false on failure.
 * Care should be taken with these functions to test for failure using ===
 * (as in, if($result !== false ) {...}) because not using === or !== may
 * result in unexpected ceorcion of a valid response (0) to false.
 *
 *****************************************************************************/

date_default_timezone_set('UTC');

/**
 * Performs any resource agnostic preflight validation and can set generic response values.
 * If the request fails any checks, preflight should return false and set appropriate
 * HTTP response codes and a failure message.  Returning false will prevent the requested
 * resource from being called.
 */
function preflight(&$request, &$response, &$db) {
  $response->set_http_code(200);
  $response->success("Request OK");
  log_to_console("OK");

  return true;
}

/**
 * Tries to sign up the username with the email and password.
 * The username and email must be unique and valid, and the password must be valid.
 * Note that it is fine to rely on database constraints.
 */
function signup(&$request, &$response, &$db) {
  $username = $request->param("username");
  $password = $request->param("password");
  $email    = $request->param("email");

  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $response->set_http_code(400);
    $response->failure("Error when creating account.");
    log_to_console("Invalid email address");
    return false;
  }

  # Generate a random salt
  $salt = rand_str();

  # Try to insert a new user
  try {
    $stmt = $db->prepare("INSERT INTO user (username, passwd, email, modified) VALUES (:username, :password, :email, :modified);");

    $now = new DateTime();
    $stmt->execute(array(
      ':username' => $username,
      ':password' => hash('sha256', $password . $salt),
      ':email'    => $email,
      ':modified' => $now->format('Y-m-d H:i:s'),
    ));

    $stmt = $db->prepare("INSERT INTO user_login (username, salt) VALUES (:username, :salt);");

    $stmt->execute(array(
      ':username' => $username,
      ':salt' => $salt,
    ));
  } catch(PDOException $e) {
    $response->set_http_code(400);
    $response->failure("Error when creating account.");
    log_to_console($e->getMessage());
    return false;
  }

  $response->set_http_code(201);
  $response->success("Account created.");
  log_to_console("Account created.");

  return true;
}

/**
 * Handles identification requests.
 * This resource should return any information the client will need to produce
 * a log in attempt for the given user.
 * Care should be taken not to leak information!
 */
function identify(&$request, &$response, &$db) {
  $username = $request->param("username");

  # Search database for username
  $stmt = $db->query("SELECT * FROM user WHERE username=:username;");
  $stmt->execute(array(
    ':username' => $username,
  ));
  $users = $stmt->fetchAll();

  # Return error if user not found
  if (count($users) != 1) {
    $response->set_http_code(400);
    $response->failure("Error when identifying user.");
    log_to_console("Username not exist");
    return false;
  }

  # Grab the user
  $user = $users[0];

  # Search database for user_login
  $stmt = $db->query("SELECT * FROM user_login WHERE username=:username;");
  $stmt->execute(array(
    ':username' => $username,
  ));
  $logins = $stmt->fetchAll();
  $login = $logins[0];

  # Grab the salt
  $salt      = $login['salt'];
  $challenge = rand_str();

  # Try to update a new challenge
  try {
    $stmt = $db->prepare("UPDATE user_login SET challenge=:challenge;");

    $stmt->execute(array(
      ':challenge' => $challenge
    ));
  } catch(PDOException $e) {
    $response->set_http_code(400);
    $response->failure("Error when identifying account.");
    log_to_console($e->getMessage());
    return false;
  }

  # Return salt and challenge to user
  $response->set_data('salt', $salt);
  $response->set_data('challenge', $challenge);

  $response->set_http_code(200);
  $response->success("Successfully identified user.");
  log_to_console("Success.");

  return true;
}

/**
 * Handles login attempts.
 * On success, creates a new session.
 * On failure, fails to create a new session and responds appropriately.
 */
function login(&$request, &$response, &$db) {
  $username  = $request->param("username");
  $password  = $request->param("password");

  # Search database for user
  $stmt = $db->query("SELECT * FROM user WHERE username=:username;");
  $stmt->execute(array(
    ':username' => $username,
  ));
  $users = $stmt->fetchAll();
  $user = $users[0];

  # Search database for user_login
  $stmt = $db->query("SELECT * FROM user_login WHERE username=:username;");
  $stmt->execute(array(
    ':username' => $username,
  ));
  $user_logins = $stmt->fetchAll();
  $user_login = $user_logins[0];

  # Process the challenge
  $password_challenge = hash('sha256', $user['passwd'] . $user_login['challenge']);

  # Check the challenge solution from client is correct
  if ($password != $password_challenge) {
    $response->set_http_code(400);
    $response->failure("Error when login user.");
    log_to_console("Challenge solution failed");
    return false;
  }

  # TODO: flip valid flag

  # Generate a random sessionid and token
  $sessionid = rand_str();
  $token     = rand_str();

  # Try to insert a new session record
  try {
    $stmt = $db->prepare("INSERT INTO user_session (sessionid, username, expires) VALUES (:sessionid, :username, :expires);");

    $now = new DateTime();
    $interval = new DateInterval("PT15M");
    $now_str = $now->add($interval)->format('Y-m-d H:i:s');

    $stmt->execute(array(
      ':sessionid' => $sessionid,
      ':username'  => $username,
      ':expires'   => $now_str,
    ));

    $stmt = $db->prepare("INSERT INTO web_session (sessionid, expires, metadata) VALUES (:sessionid, :expires, :metadata);");

    $stmt->execute(array(
      ':sessionid' => $sessionid,
      ':expires'   => $now_str,
      ':metadata'  => $token,
    ));
  } catch(PDOException $e) {
    $response->set_http_code(400);
    $response->failure("Error when login user.");
    log_to_console($e->getMessage());
    return false;
  }

  # Set cookies for user session
  $response->add_cookie('username', $username);
  $response->add_cookie('sessionid', $sessionid);

  # Add token for user session
  $response->set_token('token', $token);

  $response->set_http_code(200);
  $response->success("Successfully logged in.");
  log_to_console("Session created.");
  return true;
}

/**
 * Returns the sites for which a password is already stored.
 * If the session is valid, it should return the data.
 * If the session is invalid, it should return 401 unauthorized.
 */
function sites(&$request, &$response, &$db) {
  if (!authenticate($request, $db)) {
    $response->set_http_code(400);
    $response->failure("Failed to authenticate user.");
    return false;
  }

  # Search database for user_safe
  $stmt = $db->query("SELECT site FROM user_safe WHERE username=:username;");
  $stmt->execute(array(
    ':username' => $request->cookie('username'),
  ));
  $sites = $stmt->fetchAll();

  $map = function($site) {
    return $site['site'];
  };

  # Map the data array to string array
  $sites = array_map($map, $sites);

  # Return sites array to client
  $response->set_data("sites", $sites);

  $response->set_http_code(200);
  $response->success("Sites with recorded passwords.");
  log_to_console("Found and returned sites");

  return true;
}

/**
 * Saves site and password data when passed from the client.
 * If the session is valid, it should save the data, overwriting the site if it exists.
 * If the session is invalid, it should return 401 unauthorized.
 */
function save(&$request, &$response, &$db) {
  if (!authenticate($request, $db)) {
    $response->set_http_code(400);
    $response->failure("Failed to authenticate user.");
    return false;
  }

  $site       = $request->param("site");
  $siteuser   = $request->param("siteuser");
  $sitepasswd = $request->param("sitepasswd");
  $siteiv     = $request->param("siteiv");

  # Search database for user_safe
  $stmt = $db->query("SELECT site FROM user_safe WHERE username=:username AND site=:site;");
  $stmt->execute(array(
    ':username' => $request->cookie('username'),
    ':site'     => $site,
  ));
  $sites = $stmt->fetchAll();

  if (count($sites) == 1) {
    # Try to update the existing user safe record
    try {
      $stmt = $db->prepare("UPDATE user_safe SET site=:site, siteuser=:siteuser, sitepasswd=:sitepasswd, siteiv=:siteiv, modified=:modified WHERE username=:username AND site=:site;");

      $now = new DateTime();
      $stmt->execute(array(
        ':username'   => $request->cookie('username'),
        ':site'       => $site,
        ':siteuser'   => $siteuser,
        ':sitepasswd' => $sitepasswd,
        ':siteiv'     => $siteiv,
        ':modified'   => $now->format('Y-m-d H:i:s'),
      ));
    } catch(PDOException $e) {
      $response->set_http_code(400);
      $response->failure("Error when updating site.");
      log_to_console($e->getMessage());
      return false;
    }
  } else {
    # Try to insert the new user safe record
    try {
      $stmt = $db->prepare("INSERT INTO user_safe (username, site, siteuser, sitepasswd, siteiv, modified) VALUES (:username, :site, :siteuser, :sitepasswd, :siteiv, :modified);");

      $now = new DateTime();
      $stmt->execute(array(
        ':username'   => $request->cookie('username'),
        ':site'       => $site,
        ':siteuser'   => $siteuser,
        ':sitepasswd' => $sitepasswd,
        ':siteiv'     => $siteiv,
        ':modified'   => $now->format('Y-m-d H:i:s'),
      ));
    } catch(PDOException $e) {
      $response->set_http_code(400);
      $response->failure("Error when saving site.");
      log_to_console($e->getMessage());
      return false;
    }
  }

  $response->set_http_code(200); // OK
  $response->success("Save to safe succeeded.");
  log_to_console("Successfully saved site data");

  return true;
}

/**
 * Gets the data for a specific site and returns it.
 * If the session is valid and the site exists, return the data.
 * If the session is invalid return 401, if the site doesn't exist return 404.
 */
function load(&$request, &$response, &$db) {
  if (!authenticate($request, $db)) {
    $response->set_http_code(400);
    $response->failure("Failed to authenticate user.");
    return false;
  }

  $site     = $request->param('site');
  $username = $request->cookie('username');

  # Search database for user_safe
  $stmt = $db->query("SELECT * FROM user_safe WHERE username=:username AND site=:site;");
  $stmt->execute(array(
    ':username' => $username,
    ':site'     => $site,
  ));
  $results = $stmt->fetchAll();

  # Return error if site not found
  if (count($results) != 1) {
    $response->set_http_code(400);
    $response->failure("Error when searching for site.");
    log_to_console("Site not exist");
    return false;
  }

  $result = $results[0];

  $response->set_data('site', $result['site']);
  $response->set_data('siteiv', $result['siteiv']);
  $response->set_data('siteuser', $result['siteuser']);
  $response->set_data('sitepasswd', $result['sitepasswd']);

  $response->set_http_code(200); // OK
  $response->success("Site data retrieved.");
  log_to_console("Successfully retrieved site data");

  return true;
}

/**
 * Logs out of the current session.
 * Delete the associated session if one exists.
 */
function logout(&$request, &$response, &$db) {
  if (!authenticate($request, $db)) {
    $response->set_http_code(400);
    $response->failure("Failed to authenticate user.");
    return false;
  }

  $sessionid = $request->cookie('sessionid');

  # Try to delete the user session
  try {
    $stmt = $db->prepare("DELETE FROM user_session WHERE sessionid=:sessionid;");

    $stmt->execute(array(
      ':sessionid' => $sessionid,
    ));
  } catch(PDOException $e) {
    $response->set_http_code(400);
    $response->failure("Error when logging out.");
    log_to_console($e->getMessage());
    return false;
  }

  $response->set_http_code(200);
  $response->success("Successfully logged out.");
  log_to_console("Logged out");

  return true;
}

/**
 * Authenticate the incoming request
 */
function authenticate(&$request, &$db) {
  $username  = $request->cookie('username');
  $sessionid = $request->cookie('sessionid');
  $token     = $request->token('token');

  # Check for token of username and session id
  if (!$username || !$sessionid) {
    log_to_console("Token not set");
    return false;
  }

  # Search database for user_session
  $stmt = $db->query("SELECT * FROM user_session INNER JOIN web_session ON user_session.sessionid = web_session.sessionid WHERE user_session.sessionid=:sessionid;");
  $stmt->execute(array(
    ':sessionid' => $sessionid,
  ));
  $sessions = $stmt->fetchAll();

  # Check for session existence
  if (count($sessions) != 1) {
    log_to_console("Session not found");
    return false;
  }

  $session = $sessions[0];

  # Check for the session id is associated with the user
  if ($session['username'] != $username) {
    log_to_console("Session username mismatch");
    return false;
  }

  $now = new DateTime();

  # Check for session expiry
  if ($now > new DateTime($session['user_session.expires']) || $now > new DateTime($session['web_session.expires'])) {
    log_to_console("Session expired");
    return false;
  }

  # Check for token
  if ($token != $session['metadata']) {
    log_to_console("Token not valid");
    return false;
  }

  return true;
}

/**
 * Generate a 128-bit random string
 */
function rand_str() {
  $str = rand(); 
  return hash('md5', $str);
}

?>
