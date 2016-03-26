(defmodule elli-cloudfront
  (doc "`elli-cloudfront` convenience module.")
  ;; API exports
  (export (start 0) (stop 0)))

;;;===================================================================
;;; API
;;;===================================================================

(defun start ()
  "Start the `elli-cloudfront` application, ensuring its dependencies are started."
  (application:ensure_all_started 'elli-cloudfront))

(defun stop ()
  "Stop the `elli-cloudfront` application."
  (application:stop 'elli-cloudfront))
