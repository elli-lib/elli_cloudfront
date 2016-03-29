-module(elli_cloudfront_handler).

-include_lib("elli_cloudfront/include/elli_cloudfront.hrl").

-callback is_authorized(Req, Resource, Args) -> {ok,User} | {error,Reason} when
    Req      :: #req{},               % An elli request
    Resource :: binary(),             % A CloudFront resource (URL)
    Args     :: proplists:proplist(), % A list of elli callback args
    User     :: any(),                % A user ID
    Reason   :: any().                % A failure reason

-callback store_ticket(User, Ticket) -> ok | {error,Reason} when
    User   :: any(),                  % A user ID
    Ticket :: ticket(),               % An elli_cloudfront ticket
    Reason :: any().                  % A failure reason

-callback validate_ticket(Req, Ticket) -> {ok,Resource} | {error,Reason} when
    Req      :: #req{},               % An elli request
    Ticket   :: ticket(),             % An elli_cloudfront ticket
    Resource :: binary(),             % A CloudFront resource (URL)
    Reason   :: ticket().             % A failure reason

-callback delete_ticket(Token) -> ok | {error,Reason} when
    Token  :: binary(),               % A #ticket.token
    Reason :: any().                  % A failure reason
