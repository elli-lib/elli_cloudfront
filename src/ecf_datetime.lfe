(defmodule ecf_datetime
  (doc "Unix epoch utility functions.")
  (export (from_now 2) (from_now 1)
          (now 0)
          (days 1) (hours 1) (minutes 1)))

(defmacro bad-time-diff (diff) `(throw `#(error #(invalid-time-diff ,'diff))))

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
  ([0]                               (now))
  ([n] (when (is_integer n) (> n 0)) (+ n (now)))
  ;; `#(,n ,unit)
  ([`#(0 ,_unit)] (now))
  ([#(1 day)]     (from_now #(1 days)))
  ([#(1 hour)]    (from_now #(1 hours)))
  ([#(1 minute)]  (from_now #(1 minutes)))
  ([#(1 second)]  (from_now #(1 seconds)))
  ([`#(,n days)] (when (is_integer n) (> n 0))
   (from_now (days n)))
  ([`#(,n hours)] (when (is_integer n) (> n 0))
   (from_now (hours n)))
  ([`#(,n minutes)] (when (is_integer n) (> n 0))
   (from_now (minutes n)))
  ([`#(,n seconds)] (when (is_integer n) (> n 0))
   (from_now n))
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
