-record(ticket, {token   = error({missing,token})   :: binary(),
                 user    = error({missing,user})    :: any(),
                 service = error({missing,service}) :: binary()
                }).

-type ticket() :: #ticket{}.
