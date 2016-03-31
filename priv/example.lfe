(application:load 'elli_cloudfront)

(code:add_patha "./_build/default/plugins/color/ebin")

(defun colorize (k v) (list (color:green k) (color:red #": ") (color:yellow v)))
(defun new-cookie
  ([`#(,name ,value)]
   (apply #'colorize/2 (tuple_to_list (elli_cookie:new name value)))))

(defun pprint (format-iolist data)
  (lfe_io:format (binary_to_list (iolist_to_binary format-iolist)) data))

(defun unix->string (seconds)
  (let* ((gregorian (+ 62167219200 seconds))
         (datetime  (calendar:gregorian_seconds_to_datetime gregorian)))
    (httpd_util:rfc1123_date datetime)))

(defun now ()
  (let ((`#(,mega-secs ,secs ,_micro-secs) (os:timestamp)))
    (+ (* mega-secs 1000000) secs)))

(defun from_now ([#(1 hour)] (+ (now) 3600)))


;;;===================================================================
;;; Contrived example
;;;===================================================================

(let* ((resource   #"http://example.com/*")
       (expiry     #(1 hour))
       (args       (elli_cloudfront:get_env))
       (cookies    (elli_cloudfront:cookie_data resource expiry args))
       (date       (unix->string (now)))
       (expires    (unix->string (from_now expiry))))
  (pprint (list (color:blue #"HTTP") (color:red #"/") (color:magenta "1.1 302 ")
                (color:green (httpd_util:reason_phrase 302)) #"\n"
                (colorize #"Date"     #"~s\n")
                (colorize #"Expires"  #"~s\n")
                (colorize #"Location"
                          #"https://d123456789abcde.cloudfront.net\n")
                #"~s\n~s\n~s\n\n")
          (list* date expires (lists:map #'new-cookie/1 cookies))))
