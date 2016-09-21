# Examples

## [[elli_cloudfront:from_now/1]]

```commonlisp
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
```


## [[elli_cloudfront:from_now/2]]

```erlang
n    :: non_neg_integer(),
unit :: days | hours | minutes | seconds.
%% unless 1 =:= n, in which case
%% unit :: day | hour | minute | second
```

```commonlisp
> (from_now 0 'days)
1458994421
> (from_now 1 'hour)
1458998024
> (from_now 60 'minutes)
1458998026
```
