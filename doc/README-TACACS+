Cracking TACACS+ hashes with JtR
---------------------------------

* Extract TACACS+ hashes from the .pcap file.

  $ ../run/pcap2john.py target.pcap > hashes


* Attack these hashes using JtR Jumbo.

  $ ../run/john --format:tacacs-plus hashes


* Reducing false positives based on the raw ideas contained in PR #2926. These
  ideas were also discovered by atom from the hashcat project.

  This technique requires having (at least) two TACACS+ packets with the same
  "seq_no" (last field in the hash) value, and using the same password.

  Sample hashes which satisy both these constraints,

  $ cat hashes
  $tacacs-plus$0$6d0e1631$d623c7692ca7b12f7ecef113bea72845$c004
  $tacacs-plus$0$6d0e1631$f7711e4b904fc4a4753e923e9bf3d2cc33e9febd3d2db74b9aa6d20462c2072013c77345d7112400d7b915$c002

  Cracking these hashes results in the following pot file,

  $ cat ../run/john.pot
  $tacacs-plus$0$6d0e1631$d623c7692ca7b12f7ecef113bea72845$c004:1234
  $tacacs-plus$0$6d0e1631$d623c7692ca7b12f7ecef113bea72845$c004:2u}0K!^
  $tacacs-plus$0$6d0e1631$d623c7692ca7b12f7ecef113bea72845$c004:ei,}3W#
  $tacacs-plus$0$6d0e1631$d623c7692ca7b12f7ecef113bea72845$c004:1234
  $tacacs-plus$0$6d0e1631$d623c7692ca7b12f7ecef113bea72845$c004:i8}42d$
  $tacacs-plus$0$6d0e1631$f7711e4b904fc4a4753e923e9bf3d2cc33e9febd3d2db74b9aa6d20462c2072013c77345d7112400d7b915$c002:I[s)|~#
  $tacacs-plus$0$6d0e1631$f7711e4b904fc4a4753e923e9bf3d2cc33e9febd3d2db74b9aa6d20462c2072013c77345d7112400d7b915$c002:4XdKNPF
  $tacacs-plus$0$6d0e1631$f7711e4b904fc4a4753e923e9bf3d2cc33e9febd3d2db74b9aa6d20462c2072013c77345d7112400d7b915$c002:9bf_6z+
  $tacacs-plus$0$6d0e1631$f7711e4b904fc4a4753e923e9bf3d2cc33e9febd3d2db74b9aa6d20462c2072013c77345d7112400d7b915$c002:1234
  $tacacs-plus$0$6d0e1631$f7711e4b904fc4a4753e923e9bf3d2cc33e9febd3d2db74b9aa6d20462c2072013c77345d7112400d7b915$c002:1234

  Filtering out the false positives (thanks to atom),

  $ perl -ne 'while (<>) { chomp; /(c00\d):(.*)/ or next; $db->{$2}->{$1} = undef; } for $pw (keys %{$db}) { next if scalar keys %{$db->{$pw}} == 1; print "$pw\n" }' < ../run/john.pot
  1234

  This reveals the actual password to be "1234".
