(defmodule elli_cloudfront
  "Elli handler for signing CloudFront requests."
  (behaviour elli_handler)
  ;; elli_handler callbacks
  (export (handle 2) (handle_event 3))
  ;; CloudFront signed cookies
  (export (cookie_data 3))
  ;; CloudFront signed URL (or query params)
  (export (signed_params 3) (signed_url 3))
  ;; Config helper functions
  (export (get_env 1) (key_pair_id 1) (private_key 1))
  ;; Expiry functions
  (export (from_now 1) (from_now 2))
  (import (rename erlang ((function_exported 3) exported?))))

(include-lib "elli_cloudfront/include/elli_cloudfront.hrl")


;;;===================================================================
;;; Useful macros
;;;===================================================================

(defmacro ->
  "Thread `x` through the `sexps`.

  Insert `x` as the second item in the first `sexp`, making it a list if it is
  not a list already. If there are more `sexps`, insert the first `sexp` as the
  second item in the second `sexp`, etc."
  ([x]                   x)
  ([x `(,sexp . ,sexps)] `(,sexp ,x ,@sexps))
  ([x sexp]              `(list ,sexp ,x))
  ([x sexp . sexps]      `(-> (-> ,x ,sexp) ,@sexps)))

(defmacro ->>
  "Thread `x` through the `sexps`.

  Insert `x` as the last item in the first `sexp`, making it a list if it is
  not a list already. If there are more `sexps`, insert the first `sexp` as the
  last item in the second `sexp`, etc."
  ([x]                   x)
  ([x `(,sexp . ,sexps)] `(,sexp ,@sexps ,x))
  ([x sexp]              `(list ,sexp ,x))
  ([x sexp . sexps]      `(->> (->> ,x ,sexp) ,@sexps)))

(defmacro doto
  "Evaluate all given s-expressions and functions in order,
  for their side effects, with the value of `x` as the first argument
  and return `x`."
  (`[,x . ,sexps]
   `(let ((,'x* ,x))
      ,@(lists:map
          (match-lambda
            ([`(,f . ,args)] `(,f ,'x* ,@args))
            ([f]             `(,f ,'x*)))
          sexps)
      ,'x*)))


;;;===================================================================
;;; elli_handler callbacks
;;;===================================================================

(defun handle
  ([(= (match-req method method path path) req) args]
   (when (orelse (=:= 'GET method) (=:= 'HEAD method)))
   (cond ((=:= (get_ticket_path args)  path) (get-ticket req args))
         ((=:= (set_cookies_path args) path) (set-cookies req args))
         ('true                              'ignore)))
  ([_req _args] 'ignore))

(defun handle_event (_event _args _config) 'ok)


;;;===================================================================
;;; CloudFront cookie signing functions
;;;
;;; Based on the Ruby version in this blog post:
;;; http://www.spacevatican.org/2015/5/1/using-cloudfront-signed-cookies/
;;;
;;; cookie_data/3  returns a property list of cookies.
;;; get-ticket/2   handles GET /auth/get_ticket (or custom route)
;;; set-cookies/2  handles GET /auth/set_cookies (or custom route)
;;;===================================================================

(defun cookie_data (resource expiry args)
  "Given a binary `resource` URL, `expiry` (`` `#(,n ,unit) ``),
  return a proplist of CloudFront cookies.

  If `expiry` is invalid input to [[from_now/1]], or
  one of `` 'key_pair_id `` or `` 'private_key ``
  is missing from `args`, throw an error.

  The scope of the resultant cookie data is of the form `http*://{{host}}/*`.

  See also: [[key_pair_id/1]] and [[private_key/1]]"
  (cred->cookies (credentials resource expiry args)))

(defun cred->cookies (cred)
  (-> (match-lambda
        ([`#(policy      ,value)] `#(#"CloudFront-Policy"      ,value))
        ([`#(signature   ,value)] `#(#"CloudFront-Signature"   ,value))
        ([`#(key_pair_id ,value)] `#(#"CloudFront-Key-Pair-Id" ,value)))
      (lists:map cred)))

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

(defun params->query-string (params)
  (->> params
       (lists:map (match-lambda ([`#(,k ,v)] `[,k #"=" ,v])))
       (intersperse #"&")))

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


;;;===================================================================
;;; Config helper functions
;;;===================================================================

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

(defun get_env (priv-dir args)
  (-> (->> (let*  ((key_pair_id (key_pair_id args)) ; Validate key_pair_id
                   (key-file    (++ (binary_to_list key_pair_id) ".key")))
             (try
               (let ((`#(ok ,private_key) (->> (filename:join priv-dir key-file)
                                               (file:read_file))))
                 (cons `#(private_key ,private_key)
                       (proplists:delete 'private_key args)))
               (catch
                 (_ (throw `#(error #(missing ,key-file))))))))
      (doto (private_key))))            ; Validate private_key

(defun handler (args)
  (case (proplists:get_value 'handler args)
    ('undefined (throw #(error #(missing handler))))
    (handler    handler)))

(defun key_pair_id (args)
  "Given a proplist of `args`, return the `` 'key_pair_id ``.

  If it is missing, throw `#(error #(missing key_pair_id))`."
  (case (proplists:get_value 'key_pair_id args)
    ('undefined (throw #(error #(missing key_pair_id))))
    (value      (->> value (assert-binary 'key_pair_id)))))

(defun private_key (args)
  "Given a proplist of `args`, return the `` 'private_key ``.

  If it is missing, throw `#(error #(missing private_key))`."
  (case (proplists:get_value 'private_key args)
    ('undefined (throw #(error #(missing private_key))))
    (value      (->> value (assert-binary 'private_key)))))

(defun priv_dir (app)
  (case (code:priv_dir app)
    (#(error bad_name) (throw `#(error #(bad_name ,app))))
    (priv_dir          priv_dir)))

(defun assert-binary (k v)
  (if (is_binary v) v (throw `#(error #(non_binary ,k ,v)))))

(defun get_ticket_path (args)
  "Given a property list of `args`, return the value of `` 'get_ticket_path ``.

  Default: `` '[#\"auth\" #\"get_ticket\"] ``"
  (proplists:get_value 'get_ticket_path args '[#"auth" #"get_ticket"]))

(defun set_cookies_path (args)
  (proplists:get_value 'set_cookies_path args '[#"auth" #"set_cookies"]))


;;;===================================================================
;;; Cookie signing
;;;===================================================================

(defun policy (url expiry)
  (let* ((expiry*   (from_now expiry))
         (condition `[#(#"DateLessThan" [#(#"AWS:EpochTime" ,expiry*)])])
         (statement `[[#(#"Resource" ,url) #(#"Condition" ,condition)]]))
    (json:to_binary `[#(#"Statement" ,statement)])))

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
    ('undefined (throw `#(error #(missing service ,req))))
    (service    service)))

(defun ticket (req)
  (case (elli_request:get_arg_decoded #"ticket" req)
    ('undefined (throw `#(error #(missing ticket ,req))))
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


;;;===================================================================
;;; URL helper functions
;;;
;;; Based on:
;;; http://amtal.ca/2011/07/19/unix-pipes-pointless-functional-programming.html
;;;===================================================================

(defun get-host (url)
  (-> (strip-protocol url) (strip-path) (strip-port) (lower-case)))

(defun strip-path (url) (car (binary:split url #"/")))

(defun strip-port (url) (car (binary:split url #":")))

(defun strip-protocol
  ([(binary "http://"  (rest bytes))] rest)
  ([(binary "https://" (rest bytes))] rest)
  ([x]                                x))


;;;===================================================================
;;; List and string functions
;;;===================================================================

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

(defun intersperse
  "Given a element and a list, intersperse that element between the elemensts
  of the list. For example,

  ```lfe
  > (intersperse #\, \"abcde\")
  \"a,b,c,d,e\"
  ```

  Ported from Haskell's [`Data.List.intersperse`](https://hackage.haskell.org/package/base-4.8.2.0/docs/src/Data.OldList.html#intersperse)."
  ([_    ()]          [])
  ([sep `(,x . ,xs)] `[,x . ,(-intersperse sep xs)]))

(defun -intersperse
  ([_    ()]          [])
  ([sep `(,x . ,xs)] `[,sep ,x . ,(-intersperse sep xs)]))


;;;===================================================================
;;; Expiry functions
;;;===================================================================

(defmacro bad-time-diff (diff) `(throw `#(error #(invalid-time-diff ,'diff))))

(defun now ()
  "Return the number of seconds since the Unix epoch."
  (let ((`#(,mega-secs ,secs ,_micro-secs) (os:timestamp)))
    (+ (* mega-secs 1000000) secs)))

(defun from_now
  "Return the the number of seconds the Unix epoch `n` `unit`s from now.

  ```erlang
  n    :: non_neg_integer(),
  unit :: days | hours | minutes | seconds.
  %% unless 1 =:= n, in which case
  %% unit :: day | hour | minute | second
  ```

  #### Example Usage

  ```lfe
  > (from_now 0 'days)
  1458994421
  > (from_now 1 'hour)
  1458998024
  > (from_now 60 'minutes)
  1458998026
  ```"
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
  ([n unit] (bad-time-diff `#(,n ,unit))))

(defun from_now
  "Equivalent to [[from_now/2]] but with a single argument, `` `#(,n ,unit) ``.

  [[from_now/1]] will also accept a non-negative integer, `n`,
  and treat it as `` `#(,n seconds) ``.

  #### Example Usage

  ```lfe
  > (from_now 42)
  1458994427
  > (from_now #(0 days))
  1458994387
  > (from_now #(1 hour))
  1458997992
  > (from_now #(60 minutes))
  1458997996
  > (from_now (+ (days 1) (hours 6)))
  1459102403
  ```"
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
  ([x] (bad-time-diff x)))

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
