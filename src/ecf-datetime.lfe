(defmodule ecf-datetime
  (doc "Unix epoch utility functions.")
  (export (from-now 2) (from-now 1)
          (now 0)
          (days 1) (hours 1) (minutes 1)))

(defmacro bad-time-diff (diff) `(throw `#(error #(invalid-time-diff ,'diff))))

(defun from-now
  "Return the the number of seconds the Unix epoch `n` `unit`s from now.

```erlang
n    :: non_neg_integer(),
unit :: days | hours | minutes | seconds.
%% unless 1 =:= n, in which case
%% unit :: day | hour | minute | second
```

#### Example Usage

```lfe
> (from-now 0 'days)
1458994421
> (from-now 1 'hour)
1458998024
> (from-now 60 'minutes)
1458998026
```"
  ([0 _unit]   (now))
  ([1 'day]    (from-now 1 'days))
  ([1 'hour]   (from-now 1 'hours))
  ([1 'minute] (from-now 1 'minutes))
  ([1 'second] (from-now 1 'seconds))
  ([n 'days] (when (is_integer n) (> n 0))
   (from-now (days n)))
  ([n 'hours] (when (is_integer n) (> n 0))
   (from-now (hours n)))
  ([n 'minutes] (when (is_integer n) (> n 0))
   (from-now (minutes n)))
  ([n 'seconds] (when (is_integer n) (> n 0))
   (from-now n))
  ([n unit] (bad-time-diff `#(,n ,unit))))

(defun from-now
  "Equivalent to [[from-now/2]] but with a single argument, `` `#(,n ,unit) ``.

[[from-now/1]] will also accept a non-negative integer, `n`,
and treat it as `` `#(,n seconds) ``.

#### Example Usage

```lfe
> (from-now 42)
1458994427
> (from-now #(0 days))
1458994387
> (from-now #(1 hour))
1458997992
> (from-now #(60 minutes))
1458997996
> (from-now (+ (days 1) (hours 6)))
1459102403
```"
  ;; n seconds
  ([0]                               (now))
  ([n] (when (is_integer n) (> n 0)) (+ n (now)))
  ;; `#(,n ,unit)
  ([`#(0 ,_unit)] (now))
  ([#(1 day)]     (from-now #(1 days)))
  ([#(1 hour)]    (from-now #(1 hours)))
  ([#(1 minute)]  (from-now #(1 minutes)))
  ([#(1 second)]  (from-now #(1 seconds)))
  ([`#(,n days)] (when (is_integer n) (> n 0))
   (from-now (days n)))
  ([`#(,n hours)] (when (is_integer n) (> n 0))
   (from-now (hours n)))
  ([`#(,n minutes)] (when (is_integer n) (> n 0))
   (from-now (minutes n)))
  ([`#(,n seconds)] (when (is_integer n) (> n 0))
   (from-now n))
  ([x] (bad-time-diff x)))

(defun now ()
  "Return the number of seconds since the Unix epoch."
  (let ((`#(,mega-secs ,secs ,_micro-secs) (os:timestamp)))
    (+ (* mega-secs 1000000) secs)))

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
