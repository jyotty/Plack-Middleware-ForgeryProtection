use strict;
use Test::More;
use Plack::Test;
use Plack::Builder;
use Plack::Request;
use HTTP::Request::Common;
use HTTP::Cookies;

my $app = sub { 
    my $env = shift;
    if ($env->{REQUEST_METHOD} eq 'GET') {
        return [ 200, [ 'Content-Type' => 'text/html' ], [ $env->{'psgix.session'}{'_csrf_token'} ] ];
    } else {
        return [ 200, [ 'Content-Type' => 'text/html' ], [ 'Hello' ] ];
    }   
};   

$app = builder {
    enable 'Session';
    enable 'ForgeryProtection';
    $app;
};

test_psgi app => $app, client => sub {
    my $cb = shift;

    my $res = $cb->(POST '/');
    is $res->code, 403;

    $res = $cb->(POST '/', {'_csrf_token' => 'bad token'});
    is $res->code, 403;

    my $jar = HTTP::Cookies->new;

    $res = $cb->(GET '/');
    $jar->extract_cookies($res);
    my $token = $res->content;
    
    my $req = POST '/', {'_csrf_token' => $token};
    $jar->add_cookie_header($req);
    $res = $cb->($req);
    is $res->code, 200; 
};
done_testing;
