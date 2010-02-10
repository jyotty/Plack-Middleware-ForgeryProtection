use strict;
use Test::More;
use Plack::Test;
use Plack::Builder;
use Plack::Request;
use HTTP::Request::Common;
use LWP::UserAgent;
use HTTP::Cookies;

$Plack::Test::Impl = 'Server';

my $app = sub { 
    my $env = shift;
    my $session = $env->{'psgix.session'};

    if ($env->{REQUEST_METHOD} eq 'GET') {
        return [ 200, [ 'Content-Type' => 'text/html' ], [ $session->{'_csrf_token'} ] ];
    } else {
        return [ 200, [ 'Content-Type' => 'text/html' ], [ 'Hello' ] ];
    }   
};   

$app = builder {
    enable 'Session';
    enable 'ForgeryProtection';
    $app;
};

my $ua = LWP::UserAgent->new;
$ua->cookie_jar( HTTP::Cookies->new );

test_psgi ua => $ua, app => $app, client => sub {
    my $cb = shift;

    my $res = $cb->(POST '/');
    is $res->code, 403;

    $res = $cb->(POST '/', {'_csrf_token' => 'bad token'});
    is $res->code, 403;

    $res = $cb->(GET '/');
    my $token = $res->content;
    
    my $req = POST '/', {'_csrf_token' => $token};
    $res = $cb->($req);
    is $res->code, 200; 
};
done_testing;
