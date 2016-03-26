(defmodule ecf-sup
  (doc "`elli-cloudfront` top-level supervisor.")
  (behaviour supervisor)
  ;; API exports
  (export (start_link 0))
  ;; Supervisor callbacks
  (export (init 1)))

(defun SERVER () (MODULE))


;;;===================================================================
;;; API
;;;===================================================================

(defun start_link ()
  "Create a supervisor process as part of a supervision tree."
  (supervisor:start_link `#(local ,(SERVER)) (MODULE) []))


;;;===================================================================
;;; Internal functions
;;;===================================================================

(defun init (_args)
  "Return the supervisor flags and child specifications."
  #(ok #m(strategy one_for_one intensity 0 period 1) []))
