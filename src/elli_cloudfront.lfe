(defmodule elli_cloudfront
  (doc "CloudFront cookie signing handler.")
  (behaviour elli_handler)
  ;; CloudFront signed cookie
  (export (cookie_data 3))
  ;; Token generation
  (export (new_token 0) (new_token 1))
  ;; Args helper functions
  (export (opts 0)
          (key_pair_id 1) (private_key 1)
          (get_ticket_path 1) (set_cookies_path 1))
  ;; elli_handler callbacks
  (export (handle 2) (handle_event 3)))

(include-lib "clj/include/compose.lfe")

(include-lib "elli_cloudfront/include/elli_cloudfront.hrl")


;;;===================================================================
;;; CloudFront cookie signing functions
;;;
;;; Based on the Ruby version in this blog post:
;;; http://www.spacevatican.org/2015/5/1/using-cloudfront-signed-cookies/
;;;===================================================================

(defun cookie_data (resource expiry args)
  "Given a `resource` URL, `expiry` and proplist of `args`.
return a proplist of CloudFront cookies.

If `expiry` is invalid input to [[ecf_datetime:from_now/1]], or
one of `` 'key_pair_id `` or `` 'private_key ``
is missing from `args`, throw an error.

See also: [[key_pair_id/1]] and [[private_key/1]]"
  (let ((raw-policy (policy resource expiry)))
    `[#(#"CloudFront-Policy"      ,(safe-base64 raw-policy))
      #(#"CloudFront-Signature"   ,(sign raw-policy (private_key args)))
      #(#"CloudFront-Key-Pair-Id" ,(key_pair_id args))]))


;;;===================================================================
;;; Token generation functions
;;;===================================================================

(defun new_token ()
  "Equivalent to `(funcall #'`[[new_token/1]] ` 40)`."
  (new_token 40))

(defun new_token (n)
  "Generate `n` bytes randomly uniform `0..255`, and return the result
URL-safe base64 encoded, i.e. with `+=/` replaced with `-_~`, respectively."
  (safe-base64 (crypto:strong_rand_bytes n)))


;;;===================================================================
;;; elli_handler callbacks
;;;===================================================================


(defun handle
  ([(= (match-req method method path path) req) args]
   (cond
    ((=:= (get_ticket_path args)  path) (get-ticket req args))
    ((=:= (set_cookies_path args) path) (set-cookies req args))
    ('true                             'ignore)))
  ([req _args]
   'ignore))

(defun get-ticket (req args)
  (let ((handler (handler args))
        (service (service req)))
    (case (authorized? handler service req args)
      (`#(ok ,user)
       (case (create-ticket! handler service user)
         (`#(ok ,token) (redirect service token args))
         ;; TODO: 500
         (_other         'ignore)))
      ;; TODO: 401
      ('false 'ignore))))

(defun authorized? (handler service req args)
  (andalso (erlang:function_exported handler 'is_authorized 3)
           (case (call handler 'is_authorized req service args)
             (`#(ok ,user) `#(ok ,user))
             (_            'false))))

(defun create-ticket! (handler service user)
  (if (erlang:function_exported handler 'store_ticket 2)
    (let ((ticket (make-ticket token (new_token) user user service service)))
      (case (call handler 'store_ticket user ticket)
        ('ok                `#(ok ,(ticket-token ticket)))
        (`#(error ,_reason) #(error store_ticket))))
    `#(error #(undef ,handler store_ticket))))


(defun set-cookies (req args)
  (let ((handler (handler args)))
    (case (validate-ticket handler req)
      ;; TODO: 401
      ('false 'ignore)
      (`#(ok ,token ,service)
       (if (delete-ticket! handler token)
         ;; TODO: access control
         (let* ((service-host (get-host service))
                (headers
                 (-> (host->resource service-host)
                     (cookie_data #(2 hours) args)
                     (->> (lists:map #'new-cookie/1)
                          ;; TODO: pull out into redirect function
                          (cons `#(#"Location" ,(binary "https://" (service-host binary))))))))
           `#(302 ,headers #""))
         ;; TODO: 500
         'ignore)))))

(defun validate-ticket (handler req)
  (andalso (erlang:function_exported handler 'validate_ticket 2)
           (let ((token (ticket req)))
             (case (call handler 'validate_ticket req token)
               (`#(ok ,service)    `#(ok ,token ,service))
               (`#(error ,_reason) 'false)))))

(defun delete-ticket! (handler token)
  (andalso (erlang:function_exported handler 'delete_ticket 1)
           (case (call handler 'delete_ticket token)
             ('ok                'true)
             (`#(error ,_reason) 'false))))

(defun new-cookie ([`#(,name ,value)] (elli_cookie:new name value)))

(defun handle_event
  (['elli_startup args config]   'ok)
  ([_event        _args _config] 'ok))


;;;===================================================================
;;; Args helper functions
;;;===================================================================

(defun opts ()
  (lists:filter
    (match-lambda
      ([`#(key_pair_id ,_)] 'true)
      ([`#(private_key ,_)] 'true)
      ([_]                             'false))
    (application:get_all_env 'elli_cloudfront)))

(defun get_ticket_path (args)
  "Given a property list of `args`, return the value of `` 'get_ticket_path ``.

Default: `` '[#\"auth\" #\"get_ticket\"] ``"
  (proplists:get_value 'get_ticket_path args '[#"auth" #"get_ticket"]))

(defun set_cookies_path (args)
  (proplists:get_value 'set_cookies_path args '[#"auth" #"set_cookies"]))

(defun handler (args)
  (case (proplists:get_value 'handler args)
    ('undefined (throw #(error #(missing handler))))
    (handler    handler)))

(defun key_pair_id (args)
  "Given a proplist of `args`, return the `` 'key_pair_id ``.

If it is missing, throw `#(error #(missing key_pair_id))`."
  (case (proplists:get_value 'key_pair_id args)
    ('undefined  (throw #(error #(missing key_pair_id))))
    (key_pair_id key_pair_id)))

(defun private_key (args)
  "Given a proplist of `args`, return the `` 'private_key ``.

If it is missing, throw `#(error #(missing private_key))`."
  (case (proplists:get_value 'private_key args)
    ('undefined  (throw #(error #(missing private_key))))
    (private_key private_key)))


;;;===================================================================
;;; Internal functions
;;;===================================================================

(defun req->resource (req) (host->resource (get-host (service req))))

(defun host->resource (host) (binary "http*://" (host binary) "/*"))

(defun service (req)
  (case (elli_request:get_arg_decoded #"service" req)
    ('undefined (throw `#(error #(missing service ,req))))
    (service    service)))

(defun ticket (req)
  (case (elli_request:get_arg_decoded #"ticket" req)
    ('undefined (throw `#(error #(missing ticket ,req))))
    (token      token)))

(defun policy (url expiry)
  (let* ((expiry*   (ecf_datetime:from_now expiry))
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

(defun fold-replace (string pairs) (fold-replace string pairs 'binary))

(defun fold-replace (string pairs return-type)
  (lists:foldl
    (match-lambda
      ([`#(,patt ,replacement) acc]
       (re:replace acc patt replacement `[global #(return ,return-type)])))
    string pairs))

(defun get-host (url)
  (-> (strip-protocol url) (strip-path) (strip-port) (lower-case)))

(defun strip-path (url) (car (binary:split url #"/")))

(defun strip-port (url) (car (binary:split url #":")))

(defun strip-protocol
  ([(binary "http://"  (rest bytes))] rest)
  ([(binary "https://" (rest bytes))] rest)
  ([x]                                x))

(defun lower-case
  "Convert a given `bin`ary or `str`ing to all lower-case."
  ([bin] (when (is_binary bin)) (lower-case (binary_to_list bin)))
  ([str] (when (is_list str))   (list_to_binary (string:to_lower str))))

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


(defun redirect (service token args)
  (redirect [] service token args))

(defun redirect (headers service token args)
  (let ((location `[#"https://" ,(get-host service) #"/"
                    ,(intersperse #"/" (set_cookies_path args))
                    #"?ticket=" ,token]))
    `#(302 [#(#"Location" ,(iolist_to_binary location)) . ,headers] #"")))
