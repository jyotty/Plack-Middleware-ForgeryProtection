use strict;
use Test::More;
use Plack::Test;
use Plack::Builder;
use Plack::Request;
use HTTP::Request::Common;

my $app = sub { 
    my $env = shift;
    $env->{'psgix.session'}{'_csrf_token'} = 'PCsTPTNydJ9tFJanaR/H6UYmqJ9PETC040Jb8R0V+O0=';
    if ($env->{REQUEST_METHOD} eq 'GET') {
        return [ 200, [ 'Content-Type' => 'text/html' ], 
            [ $env->{'psgix.session'}{'_csrf_token'} ] ];
    } else {
        my $req = Plack::Request->new($env);
        return [ 200, [ 'Content-Type' => 'text/html' ], [ 'Hello' ] ];
    }   
};   

builder {
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

    $res = $cb->(GET '/');
    my $token = $res->content;
    
    $res = $cb->(POST '/', {'_csrf_token' => $token});
    is $res->code, 200; 
};
        
done_testing;