(defmodule elli_cloudfront
  (doc "CloudFront cookie signing handler.")
  (behaviour elli_handler)
  ;; elli_handler callbacks
  (export (handle 2) #|(handle_event 3)|#)
  ;; CloudFront signed cookie
  (export (cookie_data 3))
  ;; Config helper function
  (export (get_env 0)))

(include-lib "clj/include/compose.lfe")

(include-lib "elli_cloudfront/include/elli_cloudfront.hrl")

(defmacro doto
  "Evaluate all given s-expressions and functions in order,
for their side effects, with the value of `x` as the first argument
and return `x`."
  (`(,x . ,sexps)
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

#|
(defun handle_event
  (['elli_startup args config]
   'ok)
  ([_event        _args _config] 'ok))
|#


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
  "Given a `resource` URL, `expiry` and proplist of `args`.
return a proplist of CloudFront cookies.

If `expiry` is invalid input to [[from_now/1]], or
one of `` 'key_pair_id `` or `` 'private_key ``
is missing from `args`, throw an error.

See also: [[key_pair_id/1]] and [[private_key/1]]"
  (let ((raw-policy (policy resource expiry)))
    `[#(#"CloudFront-Policy"      ,(safe-base64 raw-policy))
      #(#"CloudFront-Signature"   ,(sign raw-policy (private_key args)))
      #(#"CloudFront-Key-Pair-Id" ,(key_pair_id args))]))

(defun get-ticket (req args)
  (let ((handler (handler args))
        (service (service req)))
    (case (authorized? handler service req args)
      ('false #(401 [] #""))
      (`#(ok ,user)
       (case (create-ticket handler service user)
         (`#(ok ,token) (redirect (set_cookies_location service token args)))
         (_other        #(500 [] #"")))))))

(defun authorized? (handler service req args)
  (andalso (erlang:function_exported handler 'is_authorized 3)
           (case (call handler 'is_authorized req service args)
             (`#(ok ,user) `#(ok ,user))
             (_            'false))))

(defun create-ticket (handler service user)
  (if (erlang:function_exported handler 'store_ticket 2)
    (let ((ticket (make-ticket token (new_token) user user service service)))
      (case (call handler 'store_ticket user ticket)
        ('ok                `#(ok ,(ticket-token ticket)))
        (`#(error ,_reason) #(error store_ticket))))
    `#(error #(undef ,handler store_ticket))))

(defun set-cookies (req args)
  (let ((handler (handler args)))
    (case (validate-ticket handler req)
      ('false #(401 [] #""))
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
  (andalso (erlang:function_exported handler 'validate_ticket 2)
           (let ((token (ticket req)))
             (case (call handler 'validate_ticket req token)
               (`#(ok ,service)    `#(ok ,token ,service))
               (`#(error ,_reason) 'false)))))

(defun delete-ticket (handler token)
  (andalso (erlang:function_exported handler 'delete_ticket 1)
           (case (call handler 'delete_ticket token)
             ('ok                'true)
             (`#(error ,_reason) 'false))))


;;;===================================================================
;;; Config helper functions
;;;===================================================================

(defun get_env ()
  "Return a property list with keys, `` 'key_pair_id `` and `` 'private_key ``.

If either are missing, throw a descriptive error."
  (doto (-> (match-lambda
              ([`#(key_pair_id ,_)] 'true)
              ([`#(private_key ,_)] 'true)
              ([_]                  'false))
            (lists:filter (application:get_all_env (MODULE))))
    (key_pair_id)                       ; Validate key_pair_id
    (private_key)))                     ; Validate private_key

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
    ,(intersperse #"/" (set_cookies_path args))
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
