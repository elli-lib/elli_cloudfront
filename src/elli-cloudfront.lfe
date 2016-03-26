(defmodule elli-cloudfront
  (doc "CloudFront cookie signing functions.")
  ;; CloudFront cookie signing functions
  (export (cookie-data 2)
          (new-ticket 0) (new-ticket 1)))

;;;===================================================================
;;; CloudFront cookie signing functions
;;;
;;; Based on the Ruby version in this blog post:
;;; http://www.spacevatican.org/2015/5/1/using-cloudfront-signed-cookies/
;;;===================================================================

(defun cookie-data (resource expiry)
  "Return a property list of CloudFront cookies.

`resource` is a URL and `expiry` is valid input to [[ecf-datetime:from-now/1]]."
  (let ((raw-policy (policy resource expiry)))
    `[#(#"CloudFront-Policy"      ,(safe-base64 raw-policy))
      #(#"CloudFront-Signature"   ,(sign raw-policy))
      #(#"CloudFront-Key-Pair-Id" ,(cloudfront-key-pair-id))]))

(defun new-ticket ()
  "Equivalent to `(funcall #'`[[new-ticket/1]] ` 40)`."
  (new-ticket 40))

(defun new-ticket (n)
  "Generate `n` bytes randomly uniform `0..255`, and return the result
URL-safe base64 encoded, i.e. with `+=/` replaced with `-_~`, respectively."
  (safe-base64 (crypto:strong_rand_bytes n)))


;;;===================================================================
;;; Internal functions
;;;===================================================================

(defun policy (url expiry)
  (let* ((expiry*   (ecf-datetime:from-now expiry))
         (condition `[#(#"DateLessThan" [#(#"AWS:EpochTime" ,expiry*)])])
         (statement `[[#(#"Resource" ,url) #(#"Condition" ,condition)]]))
    (json:to_binary `[#(#"Statement" ,statement)])))

(defun safe-base64 (data)
  (fold-replace (base64:encode data)
    '[#("\\+" "-") #("=" "_") #("/" "~")]))

(defun sign (data)
  (safe-base64 (crypto:hmac 'sha (cloudfront-private-key) data)))

(defun fold-replace (string pairs) (fold-replace string pairs 'binary))

(defun fold-replace (string pairs return-type)
  (lists:foldl
    (match-lambda
      ([`#(,patt ,replacement) acc]
       (re:replace acc patt replacement `[global #(return ,return-type)])))
    string pairs))


(defun cloudfront-key-pair-id ()
  (case (application:get_env (MODULE) 'CloudFront-Key-Pair-Id)
    ('undefined          (throw #(error missing-key-pair-id)))
    (`#(ok ,key-pair-id) key-pair-id)))

(defun cloudfront-private-key ()
  (case (application:get_env (MODULE) 'CloudFront-Private-Key)
    ('undefined          (throw #(error missing-private-key)))
    (`#(ok ,private-key) private-key)))
