BEGIN {

  foreach (qw(test.cfg)) {
    -f and require "$_" and last;
  }

  # If your host cannot be contacted as localhost, change this
  $HOST     ||= '127.0.0.1';

}

1;
