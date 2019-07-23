"use strict";

/*****************************************************************************
 * This is the JavaScript file that students need to modify to implement the
 * password safe application.  The other file, client.js, should be fine
 * without modification.  That file handles page navigation, event handler
 * binding, token setting/retrieving, preflighting, and provides some
 * utility functions that this file should use for encoding/decoding strings
 * and making server requests.
 *
 * Please do not use any method other than serverRequest to make requests to
 * the server!  It handles a few things including tokens that you should not
 * reimplement.
 *
 * Most of the functions in this file handle a form submission.  These
 * are passed as arguments the input/output DOM elements of the form that was
 * submitted.  The "this" keyword for these functions is the form element
 * itself.  The functions that handle form submissions are:
 *   - login
 *   - signup
 *   - save
 *   - load
 *
 * The other functions are each called for different reasons with different
 * parameters:
 *   - loadSite -- This function is called to populate the input or output
 *                 elements of the add or load password form.   The function
 *                 takes the site to load (a string) and the form elements
 *                 as parameters.
 *   - logout -- This function is called when the logout link is clicked.
 *               It should clean up any data and inform the server to log
 *               out the user.
 *   - credentials -- This is a utility function meant to be used by the
 *                    login function.  It is not called from other client
 *                    code (in client.js)!  The purpose of providing the
 *                    outline of this function is to help guide students
 *                    towards an implementation that is not too complicated
 *                    and to give ideas about how some steps can be
 *                    accomplished.
 *
 * The utility functions in client.js are:
 *   - serverRequest -- Takes the server resource and parameters as arguments
 *                      and returns a promise with two properties:
 *                        * response (a JavaScript response object)
 *                        * json (the decoded data from the server)
 *   - showContent -- Shows the specified page of the application.  This is
 *                    how student code should redirect the site to other
 *                    pages after a user action.
 *   - status -- displays a status message at the top of the page.
 *   - serverStatus -- Takes the result of the serverRequest promise and
 *                     displays any status messages from it.  This just
 *                     avoids some code duplication.
 *   - bufferToHexString
 *   - hexStringToUint8Array
 *   - bufferToUtf8
 *   - utf8ToUint8Array
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * Look at the MDN documentation for subtle crypto!
 *      https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
 * Also, you may want to use:
 *      https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
 *
 * The subtle crypto error messages are useless.  Typical errors are due to
 * passing unexpected parameters to the functions.  Take a look at the files
 * from Tutorial 4 for examples of using
 *      crypto.subtle.importKey
 *      crypto.subtle.sign
 *      crypto.subtle.decrypt
 * You may also be interested in using
 *      crypto.subtle.encrypt
 *      crypto.subtle.digest
 *
 * The most common error is to pass a key or iv buffer that is the wrong size.
 * For AES-CBC, for example, the key must be length 16 or 32 bytes, and the
 * IV must be 16 bytes.
 *
 * To concatenate two typed Uint8Arrays (a1, a2), you can do the following:
 *      let a3 = new Uint8Array(a1.length + a2.length);
 *      a3.set(a1);
 *      a3.set(a2, a1.length);
 *
 *****************************************************************************/


/**
 * This is an async function that should return the username and password to send
 * to the server for login credentials.
 */
async function credentials(username) {
  var idResult;

  // get any information needed to log in
  idResult = await serverRequest("identify", {"username":username});
  // bail if something went wrong
  if (!idResult.response.ok) {
    serverStatus(idResult);
    return 0;
  }

  return idResult.json;
}

/**
 * Called when the user submits the log-in form.
 */
function login(userInput, passInput) {
  // get the form fields
  var username = userInput.value,
      password = passInput.value;

  credentials(username).then(function(idJson) {
    if (idJson == 0) return;

    // do any needed work with the credentials
    password = utf8ToUint8Array(username + password);
    window.crypto.subtle.digest('SHA-256', password).then(buffer1 => {
      password = utf8ToUint8Array(bufferToHexString(buffer1) + idJson['salt']);

      window.crypto.subtle.digest('SHA-256', password).then(buffer2 => {
        password = utf8ToUint8Array(bufferToHexString(buffer2) + idJson['challenge']);

        window.crypto.subtle.digest('SHA-256', password).then(buffer3 => {
          password = bufferToHexString(buffer3);

          // Send a login request to the server.
          serverRequest("login", // resource to call
            {"username":username, "password":password, "challenge":idJson['challenge']} // this should be populated with needed parameters
          ).then(function(result) {
            // If the login was successful, show the dashboard.
            if (result.response.ok) {
              // do any other work needed after successful login here
              sessionStorage.setItem('encrypt_key_component', bufferToHexString(buffer1));

              showContent("dashboard");
            } else {
              // If the login failed, show the login page with an error message.
              serverStatus(result);
            }
          });
        });
      });
    });
  });
}

/**
 * Called when the user submits the signup form.
 */
function signup(userInput, passInput, passInput2, emailInput) {
  // get the form fields
  var username  = userInput.value.trim(),
      password  = passInput.value.trim(),
      password2 = passInput2.value.trim(),
      email     = emailInput.value.trim();

  // do any preprocessing on the user input here before sending to the server
  const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  if (!re.test(String(email).toLowerCase())) {
    alert("Email not valid!");
    return false;
  }

  if (password != password2) {
    alert("Passwords are not the same!");
    return false;
  }

  var secret = utf8ToUint8Array(username + password);
  window.crypto.subtle.digest('SHA-256', secret).then(buffer => {
    password = bufferToHexString(buffer);

    // send the signup form to the server
    serverRequest("signup",  // resource to call
                  {"username":username, "password":password, "email":email} // this should be populated with needed parameters
    ).then(function(result) {
      // if everything was good
      if (result.response.ok) {

        // do any work needed if the signup request succeeded

        // go to the login page
        showContent("login");
      }
      // show the status message from the server
      serverStatus(result);
    });
  });
}

/**
 * Called when the add password form is submitted.
 */
function save(siteInput, userInput, passInput) {
  var site       = siteInput.value.trim(),
      siteuser   = userInput.value.trim(),
      sitepasswd = passInput.value.trim(),
      siteiv     = window.crypto.getRandomValues(new Uint8Array(16));

  const encrypt_key_component = sessionStorage.getItem('encrypt_key_component');
  const alg = { name: 'AES-GCM', iv: siteiv };
  crypto.subtle.importKey('raw', hexStringToUint8Array(encrypt_key_component), alg, false, ['encrypt']).then(function(key) {
    crypto.subtle.encrypt(alg, key, utf8ToUint8Array(sitepasswd)).then(function(encrypted) {
      // send the data, along with the encrypted password, to the server
      serverRequest("save",  // the resource to call
        {"site":site, "siteuser":siteuser, "sitepasswd":bufferToHexString(encrypted), "siteiv":bufferToHexString(siteiv)} // this should be populated with any parameters the server needs
      ).then(function(result) {
        if (result.response.ok) {
          // any work after a successful save should be done here

          // update the sites list
          sites("save");
        }
        // show any server status messages
        serverStatus(result);
      });
    });
  });
}

/**
 * Called when a site dropdown is changed to select a site.
 * This can be called from either the save or load page.
 * Note that, unlike all the other parameters to functions in
 * this file, siteName is a string (the site to load) and not
 * a form element.
 */
function loadSite(siteName, siteElement, userElement, passElement) {
  // do any preprocessing here
  const requiredDecryption = siteElement.tagName.toLowerCase() == 'input' &&
                             userElement.tagName.toLowerCase() == 'input' &&
                             passElement.tagName.toLowerCase() == 'input';

  serverRequest("load", // the resource to call
                {"site":siteName} // populate with any parameters the server needs
  ).then(function(result) {
    if (result.response.ok) {
      // do any work that needs to be done on success
      siteElement.value = result['json']['site'];
      userElement.value = result['json']['siteuser'];

      if (requiredDecryption) {
        const encrypt_key_component = sessionStorage.getItem('encrypt_key_component');
        const alg = { name: 'AES-GCM', iv: new hexStringToUint8Array(result['json']['siteiv']) };
        crypto.subtle.importKey('raw', hexStringToUint8Array(encrypt_key_component), alg, false, ['decrypt']).then(function(key) {
          crypto.subtle.decrypt(alg, key, hexStringToUint8Array(result['json']['sitepasswd'])).then(function(decrypted) {
            passElement.value = bufferToUtf8(decrypted);
          });
        });
      } else {
        passElement.value = result['json']['sitepasswd'];

        const input = document.createElement('input');
        input.setAttribute('type', 'hidden');
        input.setAttribute('name', 'siteiv');
        input.setAttribute('value', result['json']['siteiv']);
        document.body.appendChild(input);
      }

    } else {
      // on failure, show the login page and display any server status
      showContent("login");
      serverStatus(result);
    }
  });
}

/**
 * Called when the decrypt password button is pressed.
 */
function load(siteInput, userInput, passInput) {
  // you will need to entirely populate this function
  const siteivInput = document.body.querySelector("input[name=siteiv]");
  const encrypt_key_component = sessionStorage.getItem('encrypt_key_component');

  const alg = { name: 'AES-GCM', iv: new hexStringToUint8Array(siteivInput.value) };
  crypto.subtle.importKey('raw', hexStringToUint8Array(encrypt_key_component), alg, false, ['decrypt']).then(function(key) {
    crypto.subtle.decrypt(alg, key, hexStringToUint8Array(passInput.value)).then(function(decrypted) {
      passInput.value = bufferToUtf8(decrypted);
      document.body.removeChild(siteivInput);
    });
  });
}

/**
 * Called when the logout link is clicked.
 */
function logout() {
  // do any preprocessing needed

  // tell the server to log out
  serverRequest("logout", {}).then(function(result) {
    if (result.response.ok) {
      showContent("login");
    }
    serverStatus(result);
  });
}
