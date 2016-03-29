(defmodule example-cf-handler
  (behaviour elli_cloudfront_handler)
  ;; elli_cloudfront_handler callbacks
  (export (is_authorized 3)
          (store_ticket 2) (validate_ticket 2) (delete_ticket 1)))

;; Defines #ticket{} and includes elli.hrl
(include-lib "elli_cloudfront/include/elli_cloudfront.hrl")

(defun is_authorized (_req _service _args)
  ;; TODO:
  ;; - Parse req for user info
  ;; - Confirm or deny user is authorized to view service
  ;; - Return a user id
  #(ok #"USERID"))

(defun store_ticket (_user _ticket)
  ;; TODO: Store user's ticket
  'ok)

(defun validate_ticket (_req _token)
  ;; TODO:
  ;; - Parse req for user info
  ;; - Fetch ticket by token
  ;; - Confirm or deny that it belongs to the user
  ;; - Return the "service" associated with the ticket
  #(ok #"https://d123456789abcde.cloudfront.net"))

(defun delete_ticket (_token)
  ;; TODO: Delete the ticket with the given token
  'ok)
