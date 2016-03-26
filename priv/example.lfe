(application:load 'elli-cloudfront)

(defun colorize (k v) (list (color:green k) (color:red #": ") (color:yellow v)))

(defun new-cookie
  ([`#(,name ,value)]
   (apply #'colorize/2 (tuple_to_list (elli_cookie:new name value)))))

(code:add_patha "./_build/default/plugins/color/ebin")

(defun colorize (x y z)
  (list (color:green x) (color:magenta y) (color:magenta z)))

(defun pprint (format-iolist data)
  (lfe_io:format (binary_to_list (iolist_to_binary format-iolist)) data))

(defun unix->string (seconds)
  (let* ((gregorian (+ 62167219200 seconds))
         (datetime  (calendar:gregorian_seconds_to_datetime gregorian)))
    (httpd_util:rfc1123_date datetime)))

(let* ((resource   #"http://example.com/*")
       (expiry     #(1 hour))
       (cookies    (elli-cloudfront:cookie-data resource expiry))
       (date       (unix->string (ecf-datetime:now)))
       (expires    (unix->string (ecf-datetime:from-now expiry))))
  (pprint (list (color:blue #"HTTP") (color:red #"/") (color:magenta "1.1 301 ")
            (color:green (httpd_util:reason_phrase 301)) #"\n" 
            (colorize #"Date"     #"~s\n")
            (colorize #"Expires"  #"~s\n")
            (colorize #"Location" #"https://d123456789abcde.cloudfront.net\n")
            #"~80s...\n~s\n~s\n\n")
          (++ (list date expires) (lists:map #'new-cookie/1 cookies))))
