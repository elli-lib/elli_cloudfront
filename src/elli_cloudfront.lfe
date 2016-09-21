;;; ==================================================== [ elli_cloudfront.lfe ]

(defmodule elli_cloudfront
  "[Elli handler][1] for signing CloudFront requests.

  Based on the Ruby version in this [blog post][2].

  [1]: https://github.com/elli-lib/elli/blob/master/doc/elli_handler.md
  [2]: http://www.spacevatican.org/2015/5/1/using-cloudfront-signed-cookies/"
  (behaviour elli_handler)
  ;; elli_handler callbacks
  (export (handle 2) (handle_event 3))
  ;; CloudFront signed cookies
  (export (cookie_data 3))
  ;; CloudFront signed URL (or query params)
  (export (signed_url 3) (signed_params 3))
  ;; Config helper functions
  (export (get_env 1) (key_pair_id 1) (private_key 1))
  ;; Expiry functions
  (export (from_now 1) (from_now 2))
  (import (rename erlang ((function_exported 3) exported?))))

(include-lib "elli_cloudfront/include/elli_cloudfront.hrl")
(include-lib "lfe/include/clj.lfe")

;;; ================================================= [ elli_handler callbacks ]

(defun handle (req args)
  ;; TODO: write docstring
  (let ((path (elli_request:path req)))
    (case (elli_request:method req)
      (method (when (orelse (=:= 'GET  method)
                            (=:= 'HEAD method)))
              (cond ((=:= (get_ticket_path  args) path) (get-ticket  req args))
                    ((=:= (set_cookies_path args) path) (set-cookies req args))
                    ('true                              'ignore)))
      (_method 'ignore))))

(defun handle_event (_event _args _config)
  "Return the atom `ok`, irrespective of input, to conform to the `elli_handler`
  behaviour."
  'ok)

;;; =============================================== [ Cookie signing functions ]

(defun cookie_data (resource expiry args)
  "Given a binary `resource` URL, `expiry` (`` `#(,n ,unit) ``),
  return a proplist of CloudFront cookies.

  If `expiry` is invalid input to [[from_now/1]], or
  one of `` 'key_pair_id `` or `` 'private_key ``
  is missing from `args`, throw an error.

  The scope of the resultant cookie data is of the form `http*://{{host}}/*`.

  See also: [[key_pair_id/1]] and [[private_key/1]]"
  (cred->cookies (credentials resource expiry args)))

(defun signed_url (resource expiry args)
  "Equivalent to [[cookie_data/3]], but returns a signed URL.

  N.B. `resource` is not sanity checked at all, so it's up to you to ensure its
  correctness, and unlike [[cookie_data/3]], it is not parsed into a wildcard
  scope, but rather used as is.

  See also: [[signed_params/3]]"
  (->> (signed_params resource expiry args)
       (params->query-string)
       (list* resource #"?")
       (iolist_to_binary)))

(defun signed_params (resource expiry args)
  "Equivalent to [[signed_url/3]], but returns a proplist of URL parameters."
  (cred->params (credentials resource expiry args)))

;;; ================================================ [ Config helper functions ]

(defun get_env (app)
  "Given an `app` name, return a property list with keys,
  `` 'key_pair_id `` and `` 'private_key ``.

  If either are missing, throw a descriptive error.

  `key_pair_id` must be present in `elli_cloudfront`'s env and `private_key`
  is the contents `{{key_pair_id}}.key` in `app`'s `priv` directory.

  If the `.key` file cannot be found, throw an error."
  (->> (application:get_env (MODULE) 'key_pair_id 'undefined)
       (tuple 'key_pair_id) (list)
       (get_env (priv_dir app))))

(defun key_pair_id (args)
  "Given a proplist of `args`, return the `` 'key_pair_id ``.

  If it is missing, throw `#(error #(missing key_pair_id))`."
  (case (proplists:get_value 'key_pair_id args)
    ('undefined (error #(missing key_pair_id) (list args)))
    (value      (assert-binary 'key_pair_id value))))

(defun private_key (args)
  "Given a proplist of `args`, return the `` 'private_key ``.

  If it is missing, throw `#(error #(missing private_key))`."
  (case (proplists:get_value 'private_key args)
    ('undefined (error #(missing private_key) (list args)))
    (value      (->> value (assert-binary 'private_key)))))

;;; ======================================================= [ Expiry functions ]

(defun from_now
  "Return the the number of seconds the Unix epoch `n` `unit`s from now."
  ([0 _unit]   (now))
  ([1 'day]    (from_now 1 'days))
  ([1 'hour]   (from_now 1 'hours))
  ([1 'minute] (from_now 1 'minutes))
  ([1 'second] (from_now 1 'seconds))
  ([n 'days] (when (is_integer n) (> n 0))
   (from_now (days n)))
  ([n 'hours] (when (is_integer n) (> n 0))
   (from_now (hours n)))
  ([n 'minutes] (when (is_integer n) (> n 0))
   (from_now (minutes n)))
  ([n 'seconds] (when (is_integer n) (> n 0))
   (from_now n))
  ([n unit] (error 'invalid_time_diff (list n unit))))

(defun from_now
  "Equivalent to [[from_now/2]] but with a single argument, `` `#(,n ,unit) ``.

  [[from_now/1]] will also accept a non-negative integer, `n`,
  and treat it as `` `#(,n seconds) ``."
  ;; n seconds
  ([0] (now))
  ([n] (when (is_integer n) (> n 0))
   (+ n (now)))
  ;; `#(,n ,unit)
  ([`#(0 ,_unit)] (now))
  ([#(1 day)]     (from_now #(1 days)))
  ([#(1 hour)]    (from_now #(1 hours)))
  ([#(1 minute)]  (from_now #(1 minutes)))
  ([#(1 second)]  (from_now #(1 seconds)))
  ([`#(,n days)]    (when (is_integer n) (> n 0)) (from_now (days n)))
  ([`#(,n hours)]   (when (is_integer n) (> n 0)) (from_now (hours n)))
  ([`#(,n minutes)] (when (is_integer n) (> n 0)) (from_now (minutes n)))
  ([`#(,n seconds)] (when (is_integer n) (> n 0)) (from_now n))
  ([x] (error 'invalid_time_diff (list x))))

;;; ===================================================== [ Internal functions ]

(defun cred->cookies (cred)
  (lists:map
    (match-lambda
      ([`#(policy      ,value)] `#(#"CloudFront-Policy"      ,value))
      ([`#(signature   ,value)] `#(#"CloudFront-Signature"   ,value))
      ([`#(key_pair_id ,value)] `#(#"CloudFront-Key-Pair-Id" ,value)))
    cred))

(defun params->query-string
  ([()] ())
  ([`(#(,key ,value) . ,params)]
   (lists:foldl
     (match-lambda ([`#(,k ,v) acc] (list acc #\& k #\= v)))
     `[,key #\= ,value] params)))

(defun cred->params (cred)
  (-> (match-lambda
        ([`#(policy      ,value)] `#(#"Policy"      ,value))
        ([`#(signature   ,value)] `#(#"Signature"   ,value))
        ([`#(key_pair_id ,value)] `#(#"Key-Pair-Id" ,value)))
      (lists:map cred)))

(defun credentials (resource expiry args)
  (let ((raw-policy (policy resource expiry)))
    `[#(policy      ,(safe-base64 raw-policy))
      #(signature   ,(sign raw-policy (private_key args)))
      #(key_pair_id ,(key_pair_id args))]))

(defun get-ticket (req args)
  (let ((handler (handler args))
        (service (service req)))
    (case (authorized? handler service req args)
      ('false #(403 [] #""))
      (`#(ok ,user)
       (case (create-ticket handler service user)
         (`#(ok ,token) (redirect (set_cookies_location service token args)))
         (_other        #(500 [] #"")))))))

(defun authorized? (handler service req args)
  (andalso (exported? handler 'is_authorized 3)
           (case (call handler 'is_authorized req service args)
             (`#(ok ,user) `#(ok ,user))
             (_            'false))))

(defun create-ticket (handler service user)
  (if (exported? handler 'store_ticket 2)
    (let ((ticket (make-ticket token (new_token) user user service service)))
      (case (call handler 'store_ticket user ticket)
        ('ok                `#(ok ,(ticket-token ticket)))
        (`#(error ,_reason) #(error store_ticket))))
    `#(error #(undef ,handler store_ticket))))

(defun set-cookies (req args)
  (let ((handler (handler args)))
    (case (validate-ticket handler req)
      ('false #(403 [] #""))
      (`#(ok ,token ,service)
       (if (delete-ticket handler token)
         (let ((service-host (get-host service)))
           ;; TODO: access control
           (-> (host->resource service-host)
               (cookie_data #(2 hours) args)
               (->> (lists:map #'new-cookie/1))
               (redirect `["https://" ,service-host])))
         #(500 [] #""))))))

(defun validate-ticket (handler req)
  (andalso (exported? handler 'validate_ticket 2)
           (let ((token (ticket req)))
             (case (call handler 'validate_ticket req token)
               (`#(ok ,service)    `#(ok ,token ,service))
               (`#(error ,_reason) 'false)))))

(defun delete-ticket (handler token)
  (andalso (exported? handler 'delete_ticket 1)
           (case (call handler 'delete_ticket token)
             ('ok                'true)
             (`#(error ,_reason) 'false))))

(defun get_env (priv-dir args)
  (-> (->> (let*  ((key_pair_id (key_pair_id args)) ; Validate key_pair_id
                   (key-file    (++ (binary_to_list key_pair_id) ".key")))
             (try
               (let ((`#(ok ,private_key)
                      (file:read_file (filename:join priv-dir key-file))))
                 (lists:keystore 'private_key 1 args
                                 `#(private_key ,private_key)))
               (catch
                 (_ (error `#(missing ,key-file) (list priv-dir args)))))))
      (doto (private_key))))            ; Validate private_key

(defun handler (args)
  (case (proplists:get_value 'handler args)
    ('undefined (error #(missing handler) (list args)))
    (handler    handler)))

(defun priv_dir (app)
  (case (code:priv_dir app)
    (#(error bad_name) (error 'bad_name (list app)))
    (priv_dir          priv_dir)))

(defun assert-binary (k v)
  (if (is_binary v) v (error 'non_binary (list k v))))

(defun get_ticket_path (args)
  "Given a property list of `args`, return the value of `` 'get_ticket_path ``.

  Default: `` '[#\"auth\" #\"get_ticket\"] ``"
  (proplists:get_value 'get_ticket_path args '[#"auth" #"get_ticket"]))

(defun set_cookies_path (args)
  (proplists:get_value 'set_cookies_path args '[#"auth" #"set_cookies"]))

;;; ========================================================= [ Cookie signing ]

(defun policy (url expiry)
  (let* ((expiry*   (from_now expiry))
         (condition `[#(#"DateLessThan" [#(#"AWS:EpochTime" ,expiry*)])])
         (statement `[[#(#"Resource" ,url) #(#"Condition" ,condition)]]))
    (jsx:encode `[#(#"Statement" ,statement)])))

(defun sign (data pem-bin)
  (->> (pem->key pem-bin)
       (public_key:sign data 'sha)
       (safe-base64)))

(defun pem->key (pem-bin)
  (let ((`[,rsa-entry] (public_key:pem_decode pem-bin)))
    (public_key:pem_entry_decode rsa-entry)))

(defun safe-base64 (data)
  (fold-replace (base64:encode data)
    '[#("\\+" "-") #("=" "_") #("/" "~")]))

(defun service (req)
  (case (elli_request:get_arg_decoded #"service" req)
    ('undefined (error #(missing service) (list req)))
    (service    service)))

(defun ticket (req)
  (case (elli_request:get_arg_decoded #"ticket" req)
    ('undefined (error #(missing ticket) (list req)))
    (token      token)))

(defun set_cookies_location (service token args)
  `[#"https://" ,(get-host service) #"/"
    ,(filename:join (set_cookies_path args))
    #"?ticket=" ,token])

(defun new_token ()
  "Equivalent to `(funcall #'`[[new_token/1]] ` 40)`."
  (new_token 40))

(defun new_token (n)
  "Generate `n` bytes randomly uniform `0..255`, and return the result
  URL-safe base64 encoded, i.e. with `+=/` replaced with `-_~`, respectively."
  (safe-base64 (crypto:strong_rand_bytes n)))

(defun req->resource (req) (host->resource (get-host (service req))))

(defun host->resource (host) (binary "http*://" (host binary) "/*"))

(defun new-cookie ([`#(,name ,value)] (elli_cookie:new name value)))

(defun redirect (location) (redirect [] location))

(defun redirect (headers location)
  `#(302 [#(#"Location" ,(iolist_to_binary location)) . ,headers] #""))

;;; =================================================== [ URL helper functions ]
;;; Based on:
;;; http://amtal.ca/2011/07/19/unix-pipes-pointless-functional-programming.html
;;; ============================================================================

(defun get-host (url)
  (-> (strip-protocol url) (strip-path) (strip-port) (lower-case)))

(defun strip-path (url) (car (binary:split url #"/")))

(defun strip-port (url) (car (binary:split url #":")))

(defun strip-protocol
  ([(binary "http://"  (rest bytes))] rest)
  ([(binary "https://" (rest bytes))] rest)
  ([x]                                x))

;;; ============================================== [ List and string functions ]

(defun lower-case
  "Convert a given `bin`ary or `str`ing to all lower-case."
  ([bin] (when (is_binary bin)) (lower-case (binary_to_list bin)))
  ([str] (when (is_list   str)) (list_to_binary (string:to_lower str))))

(defun fold-replace (string pairs) (fold-replace string pairs 'binary))

(defun fold-replace (string pairs return-type)
  (lists:foldl
    (match-lambda
      ([`#(,patt ,replacement) acc]
       (re:replace acc patt replacement `[global #(return ,return-type)])))
    string pairs))
(defun now ()
  "Return the number of seconds since the Unix epoch."
  ;; TODO: Update for 18+
  (let ((`#(,mega-secs ,secs ,_micro-secs) (os:timestamp)))
    (+ (* mega-secs 1000000) secs)))

(defun days
  "Return the number of seconds in `n` days."
  ([0] 0)
  ([1] 86400)
  ([n] (when (is_integer n) (> n 0))
   (* n (days 1))))

(defun hours
  "Return the number of seconds in `n` hours."
  ([0] 0)
  ([1] 3600)
  ([n] (when (is_integer n) (> n 0))
   (* n (hours 1))))

(defun minutes
  "Return the number of seconds in `n` minutes."
  ([0] 0)
  ([1] 60)
  ([n] (when (is_integer n) (> n 0))
   (* n (minutes 1))))

;;; ==================================================================== [ EOF ]
