use inc::Module::Install;
name 'Plack-Middleware-ForgeryProtection';
all_from 'lib/Plack/Middleware/ForgeryProtection.pm';

# requires '';

tests 't/*.t';
author_tests 'xt';

test_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
