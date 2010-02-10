package Plack::Middleware::ForgeryProtection;
use strict;
use warnings;
use parent qw(Plack::Middleware);
use Crypt::Random::Source qw(get_strong);
use MIME::Base64;
use Plack::Request;

our $VERSION = '0.01';

sub call {
    my ($self, $env) = @_;

    $env->{'psgix.session'}{'_csrf_token'} ||= encode_base64(get_strong(32), '');

    if ($env->{REQUEST_METHOD} ne 'GET') {
        my $req = Plack::Request->new($env);
        if ($req->body_parameters->{'_csrf_token'} ne $env->{'psgix.session'}{'_csrf_token'}) {
            return [ 403, [ 'Content-Type' => 'text/html; charset=utf-8'], [ '403 Forbidden' ] ];
        }
    }
    return $self->app->($env);
}

1;
__END__

=head1 NAME

Plack::Middleware::ForgeryProtection - Ronco Spray-On CSRF protection

=head1 SYNOPSIS

Set it:

  enable 'Session';
  enable 'ForgeryProtection';

and forget it.

=head1 DESCRIPTION

Plack::Middleware::ForgeryProtection creates a per-session token to prevent CSRF. 
You must include the _csrf_token session key in POST/PUT/DELETE requests, by way of
embedding a hidden input:

  <form method="post" ...>
     <input type="hidden" name="_csrf_token" value="[% csrf_token %]">
  ...
  
or other methods (JS var, &c).

=head1 AUTHOR

Joshua Yotty

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
