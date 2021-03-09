#!/usr/bin/perl

# Author: philsmd
# License: public domain
# Date: January 2017

# Version:
# 0.01

# Date released:
# January 2017

# Last updated:
# 25th January 2017

# https://github.com/philsmd/itunes_backup2hashcat

# Explanation of the output format:
# 1. all binary data is outputted in hexadeximal form
# 2. there are actually 2 formats, one for IOS backups < 10.0 and one for backups starting with 10.x
#
# version less than 10:
#  $itunes_backup$*9*wpky*iter*salt**
# version 10.x hashes:
#  $itunes_backup$*10*wpky*iter*salt*dpic*dpsl

use strict;
use warnings;

#use Data::Plist::BinaryReader;

#
# Constants
#

my $MAX_PLIST_SEARCH_DISTANCE = 256;

#
# Helper functions
#

sub read_plist_file
{
  my $file_name = shift;

  my $file_content = "";

  {
    local $/ = undef;

    my $PLIST_FH;

    if (! open ($PLIST_FH, "<$file_name"))
    {
      print STDERR "Could not open file '$file_name'.\n";

      return "";
    }

    binmode ($PLIST_FH);

    $file_content = <$PLIST_FH>;

    close ($PLIST_FH);
  }

  return $file_content;
}

sub parse_manifest_file
{
  my $data = shift;

  my ($wpky, $salt, $iter, $dpic, $dpsl);

  # my $plist = Data::Plist::BinaryReader->new;
  # my $parsed_data = $plist->open_string ($data);
  # my $backup_key_bag = $parsed_data->{data}[1]->{BackupKeyBag}[1];

  my $data_len = length ($data);

  return (undef, undef, undef) if (length ($data) < 4 + 4 + 4 + 4 + 4 + 4);

  my @salt_matches = ($data =~ /SALT..../g);

  # okay, I admit this is some strange parsing, but it seems to work all the times (for me)
  # for instance, it assumes that the order is always like this: 1. salt, 2. iter, 3. wpky

  my $idx_glob = 0;

  for (my $i = 0; $i < scalar (@salt_matches); $i++)
  {
    my $idx_salt = index ($data, "SALT", $idx_glob + 0);

    last if ($idx_salt == -1);

    my $idx_iter = index ($data, "ITER", $idx_salt + 1);

    last if ($idx_iter == -1);

    my $idx_wpky = index ($data, "WPKY", $idx_iter + 1);

    last if ($idx_wpky == -1);

    # special case:

    last if ($data_len - $idx_wpky < 8); # too close to the EOF

    if ($idx_wpky - $idx_salt < $MAX_PLIST_SEARCH_DISTANCE) # some sane distance between the items
    {
      my $salt_len = substr ($data, $idx_salt + 4, 4);
      my $iter_len = substr ($data, $idx_iter + 4, 4);
      my $wpky_len = substr ($data, $idx_wpky + 4, 4);

      $idx_salt += 8;
      $idx_iter += 8;
      $idx_wpky += 8;

      $salt = substr ($data, $idx_salt, unpack ("L>", $salt_len));
      $iter = substr ($data, $idx_iter, unpack ("L>", $iter_len));
      $wpky = substr ($data, $idx_wpky, unpack ("L>", $wpky_len));

      # iter is a special case, needs to be converted to a number
      $iter = unpack ("L>", $iter);

      last;
    }

    $idx_glob = $idx_wpky + 1;
  }

  # optional also search for DPIC and DPSL (iOS 10.2+ ?)

  my @dpsl_matches = ($data =~ /DPSL..../g);

  $idx_glob = 0;

  for (my $i = 0; $i < scalar (@dpsl_matches); $i++)
  {
    my $idx_dpic = index ($data, "DPIC", $idx_glob + 0);

    last if ($idx_dpic == -1);

    my $idx_dpsl = index ($data, "DPSL", $idx_dpic + 1);

    last if ($idx_dpsl == -1);

    if ($idx_dpsl - $idx_dpic < $MAX_PLIST_SEARCH_DISTANCE)
    {
      my $dpic_len = substr ($data, $idx_dpic + 4, 4);
      my $dpsl_len = substr ($data, $idx_dpsl + 4, 4);

      $idx_dpic += 8;
      $idx_dpsl += 8;

      $dpic = substr ($data, $idx_dpic, unpack ("L>", $dpic_len));
      $dpsl = substr ($data, $idx_dpsl, unpack ("L>", $dpsl_len));

      $dpic = unpack ("L>", $dpic);

      last;
    }

    $idx_glob = $idx_dpsl + 1;
  }

  return ($wpky, $salt, $iter, $dpic, $dpsl);
}

sub itunes_plist_get_hash
{
  my $file_name = shift;

  my $hash = "";

  my $file_content = read_plist_file ($file_name);

  if (length ($file_content) > 0)
  {
    my ($WPKY, $SALT, $ITER, $DPIC, $DPSL) = parse_manifest_file ($file_content);

    if (! defined ($WPKY))
    {
      print "ERROR: WPKY could not be found in '$file_name'\n";

      return "";
    }

    if (! defined ($SALT))
    {
      print "ERROR: SALT could not be found in '$file_name'\n";

      return "";
    }

    if (! defined ($ITER))
    {
      print "ERROR: ITER could not be found in '$file_name'\n";

      return "";
    }

    if (length ($WPKY) != 40)
    {
      print "ERROR: the WPKY within the file '$file_name' should be exactly 40 bytes long\n";

      return "";
    }

    if (length ($SALT) != 20)
    {
      print "ERROR: the SALT within the file '$file_name' should be exactly 20 bytes long\n";

      return "";
    }

    if (defined ($DPSL))
    {
      if (int ($DPIC) < 1)
      {
        print "ERROR: the DPIC within the file '$file_name' has an invalid value ($DPIC)\n";

        return "";
      }

      if (length ($DPSL) != 20)
      {
        print "ERROR: the DPSL within the file '$file_name' should be exactly 20 bytes long\n";

        return "";
      }

      $hash = sprintf ("\$itunes_backup\$*10*%s*%i*%s*%i*%s", unpack ("H*", $WPKY), $ITER, unpack ("H*", $SALT), $DPIC, unpack ("H*", $DPSL));
    }
    else
    {
      $hash = sprintf ("\$itunes_backup\$*9*%s*%i*%s**", unpack ("H*", $WPKY), $ITER, unpack ("H*", $SALT));
    }
  }

  return $hash;
}

sub usage
{
  my $program_name = shift;

  print STDERR "Usage: $program_name <Manifest.plist file>...\n";
}

#
# Start
#

if (scalar (@ARGV) lt 1)
{
  usage ($0);

  exit (1);
}

foreach my $file_name (@ARGV)
{
  if (! -e $file_name)
  {
    print STDERR "WARNING: could not open file '$file_name'\n";

    next;
  }

  my $hash_buf = itunes_plist_get_hash ($file_name);

  next unless (defined ($hash_buf));
  next unless (length ($hash_buf) > 0);

  print $hash_buf . "\n";
}

exit (0);
