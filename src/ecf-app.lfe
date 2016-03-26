(defmodule ecf-app
  (doc "The `elli-cloudfront` application.")
  (behaviour application)
  ;; Application callbacks
  (export (start 2) (stop 1)))

;;;===================================================================
;;; API
;;;===================================================================

(defun start (_type _args)
  "Start the `elli-cloudfront` application."
  (ecf-sup:start_link))

(defun stop (_state)
  "Stop the `elli-cloudfront` application."
  'ok)
