#! /usr/bin/perl
# Script to generate rules for John the Ripper from rexgen rules

# Copyright © 2014 Aleksey Cherepanov <aleksey.4erepanov@gmail.com>
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

use strict;
use warnings;

use List::Util qw(max);

# # For debug printing
# use B qw(svref_2object);
# use Data::Dumper;

######################################################################
# Implementation / Worker part

# Global skip counter
# TODO: Avoid global variable. Pass it through arguments.
my $skipped = 0;

# bcc is for Bracketed Character class
my $bcc_re = qr/\[\]?(?:\\.|[^]])*\]/;
my $token_re = qr/(\\g\{\s*\d+\s*}|\\g\d+|\\.|\(\?:|[(|)]|\?|\{\s*\d+\s*(?:,\s*\d+\s*)?\}|$bcc_re|[^][{}(|)?\\])/;
# TODO: Compatibility mode.
# Compatibility: No ?, (?:, {n} (only {n,m}), \g . \10 is \1 and 0.
# TODO: Should {n} give an error or be just inactive/not-magic?
# my $token_re_compatible = qr/(\\.|[(|)]|\{\s*\d+\s*,\s*\d+\s*\}|\[\]?(?:\\.|[^]])*\]|[^][{}(|)])/;

# RegExp, String -> List
# Replaces \g{ n } with \g{n}
# Replaces \N with \g{N}
# Expands ? into {0,1} and {n} into {n,m}
sub to_tokens {
    my $re = shift;
    die "Invalid rule" unless $_[0] =~ /^$re+\z/;
    my @a = $_[0] =~ /$re/g;
    die "Invalid rule" if $_ ne join "", @a;
    # Transform tokens, expand aliases
    # TODO: \g{00} -> \g{0}
    for (@a) {
        $_ = "\\g{$1}" if /^\\g\{\s*(\d+)\s*\}\z/;
        $_ = "\\g{$1}" if /^\\(\d+)\z/;
        if ($_ eq '?') {
            $_ = '{0,1}'
        } elsif (/^\{\s*(\d+)\s*\}\z/) {
            $_ = "{$1,$1}"
        } elsif (/^\{\s*(\d+)\s*,\s*(\d+)\s*\}\z/) {
            $_ = "{$1,$2}"
        }
    }
    @a
}

# List of Arrays -> List of Arrays
# Checks parity.
# Enumerates left brackets for capturing groups.
sub check_parity {
    for (@_) {
        my $k = 0;
        my $c = 0;
        for (@$_) {
            # Parity
            $c++ if $_ eq '(' || $_ eq '(?:';
            $c-- if $_ eq ')';
            die "unexpected right bracket" if $c < 0;
            # Enumeration
            $_ = [$_, ++$k] if $_ eq '(';
            # Non-capturing groups have number 0.
            $_ = [$_, 0] if $_ eq '(?:';
            # Impossible back reference is error
            # Though possible but undefined back references are just skipped.
            # Good: (a)\1, (a\1)
            # Bad: \1(a)
            if (/\\g{(\d+)}/ && $1 > $k) {
                die "wrong back reference $_"
            }
        }
        die "unbalanced parenthesis" if $c > 0;
        # TODO: Named groups?
    }
    @_
}

# List of Arrays -> List of Arrays
sub expand_questions {
    map {
        [map {
            if ($_ eq '?') {
                '{0,1}'
            } elsif (/^\{\s*(\d+)\s*\}\z/) {
                "{$1,$1}"
            } else {
                $_
            }
        } @$_]
    } @_
}

# List of Arrays -> List of Arrays
# Expands {n,m} into variants of token sequence
sub expand_quantifiers {
    map {
        my @a = @$_;
        # List of Arrays of Tokens
        my @b = ([]);
        for my $i (0 .. $#a) {
            if ($a[$i] =~ /^\{\s*(\d+)\s*,\s*(\d+)\s*\}\z/) {
                # Quantifier
                if ($i == 0
                    || ref $a[$i - 1] eq 'ARRAY'
                    || $a[$i - 1] eq '|') {
                    die "misplaced quantifier";
                }
                my $lower = $1;
                my $upper = $2;
                if ($lower > $upper) {
                    die "Quantifier {n,m} with n > m should not be used";
                }
                my @to_remove;
                for (0 .. $#b) {
                    my $bi = $_;
                    my $r = $b[$_];
                    my $start = $#$r;
                    my $end = $#$r;
                    if ($$r[$end] eq ')') {
                        # Seek back for paired bracket.
                        my $k = 1;
                        while ($start >= 0 && $k > 0) {
                            $start--;
                            $k++ if $$r[$start] eq ')';
                            $k-- if ref $$r[$start] eq "ARRAY";
                        }
                        if ($start < 0 && $k != 0) {
                            die "BUG: unbalanced parenthesis after check";
                        }
                    }
                    if ($upper == 0) {
                        # PCRE allow {0} and {0,0}.
                        # Remove variant with tail if {0,0}.
                        warn "Met {0,0} quantifier, part was removed.";
                        unshift @to_remove, $bi;
                    } else {
                        my @n = @$r[0 .. $start - 1];
                        my @t = @$r[$start .. $end];
                        # Remove tail if {0,m}
                        push @b, [@n] if $lower == 0;
                        # Remove variant with 1 tail if n > 1.
                        unshift @to_remove, $bi if $lower > 1;
                        # We already have variant with 1 tail.
                        $lower++ if $lower == 1;
                        for ($lower .. $upper) {
                            # TODO: Faster? push @b, [@$r]; push @$r, @t; ...
                            push @b, [@n, (@t) x $_];
                        }
                    }
                }
                delete @b[@to_remove];
                @b = grep { defined } @b;
            } else {
                # Any token except quantifier
                my $t = $a[$i];
                push @$_, $t for @b;
            }
        }
        @b
    } @_
}

# List of Arrays -> List of Arrays
# Joins tokens: ( (?: | ) are separate
# Removes backslashes everywhere except: \( \| \) [...] \\ \[ \] \g...
# TODO: Is \] really should not be replaced here?
my %no_replace = map { $_, 1 } qw/( | ) \\ [ ] g/;
sub join_tokens {
    map {
        my @a = @$_;
        # List of Tokens
        my @b;
        my $t = '';
        for (@a) {
            if (ref eq "ARRAY" || $_ eq '|' || $_ eq ')') {
                push @b, $t if $t ne '';
                push @b, $_;
                $t = '';
            } else {
                unless (/^\[/) {
                    s/\\(.)/$no_replace{$1} ? $& : $1/ge;
                }
                $t .= $_;
            }
        }
        push @b, $t if $t ne '';
        [@b]
    } @_
}

# Data structure to mangle in combine() and to return from
# parse_part() and parse_group(): each variant is represented as
# [[vector of groups' values for back references], string of a variant],
# so each function returns one or a list of such structures.

# Args: string, values of back refs (no vectors)
# Returns list: new value, modified?, max ref number
# TODO: max ref number is not actually used anywhere.
sub expand_back_refs {
    my $value = shift;
    my @refs = @_;
    my $changed = 0;
    my @nums = $value =~ /\\g\{(\d+)\}/g;
    # We expand back refs from higher numbers to lower numbers.
    # I.e. \g{12} before \g{3}.
    @nums = sort { $b <=> $a } @nums;
    for (@nums) {
        $value =~ s/\\g\{($_)\}|\\./
            defined $1 && $1 && defined $refs[$1]
                ? $refs[$changed = $1]
                : $&
             /ge;
    }
    # warn "ebrs(): " . Dumper $value, $changed;
    ($value, $changed, shift @nums)
}

# [a b], [1 2] -> a1 a2 b1 b2
# The first list could be empty, the second list could not be empty.
sub combine { #_i {
    # warn "combine 0: " . Dumper $_[0];
    # warn "combine 1: " . Dumper $_[1];
    my @a = @{shift()};
    my @b = @{shift()};
    if (@a) {
        grep { defined } map {
            my $a_value = $$_[1];
            my @a_refs = @{$$_[0]};
            # We skip variants like (a\1).
            if ((expand_back_refs $a_value, @a_refs)[1]) {
                $skipped++;
                undef
            } else {
                map {
                    my $b_value = (expand_back_refs $$_[1], @a_refs)[0];
                    my @b_refs = @{$$_[0]};
                    [[map {
                        defined($b_refs[$_])
                            ? $b_refs[$_]
                            : $a_refs[$_]
                      } 0 .. max($#a_refs, $#b_refs)],
                     $a_value . $b_value]
                } @b;
            }
        } @a
    } else {
        @b
    }
}

# sub combine {
#     my @r = combine_i(@_);
#     warn "combine result: " . Dumper([@r]) . "---\n";
#     @r
# }

sub parse_part;

sub parse_group {
    # warn "parse_group: @{$_[0]}\n";
    my $current_group = shift()->[1];
    # warn ">>1 $current_group";
    my @all;
    my @current_branch;
    while (@{$_[0]} && $_[0][0] ne ')') {
        while (@{$_[0]} && $_[0][0] ne '|' && $_[0][0] ne ')') {
            my @p = parse_part($_[0]);
            @current_branch = combine [@current_branch], [@p];
        }
        shift @{$_[0]} if @{$_[0]} && $_[0][0] eq '|';
        # Current branch is finished. We remember the value as group's
        # value to be used for back references.
        if ($current_group) {
            $$_[0][$current_group] = $$_[1] for @current_branch;
            # warn "aad" . Dumper $_;
        }
        push @all, @current_branch;
        @current_branch = ();
    }
    shift @{$_[0]};
    @all
}

sub parse_part {
    # warn "parse_part: @{$_[0]}\n";
    die "expected more" unless @_;
    my $p = shift @{$_[0]};
    ref $p eq 'ARRAY' ? parse_group($p, $_[0]) : [[], $p]
}

sub expand_parenthesis {
    my @a;
    while (@_) {
        my @b = parse_part \@_;
        # warn "top\n";
        @a = combine [@a], [@b];
        # %% toplevel |
    }
    # warn Dumper [@a];
    grep { defined } map {
        my $value = $$_[1];
        my @refs = @{$$_[0]};
        # warn "b4 ebr: " . Dumper $value, [@refs];
        # If there are still backrefs after that. We need to skip this
        # variant.
        my $r = (expand_back_refs $value, @refs)[0];
        my $f = 1;
        if (grep { $_ } $r =~ /\\[][]|$bcc_re|\\g\{(\d+)\}/g) {
            $f = 0;
            $skipped++;
        }
        $f ? $r : undef
    } @a
}

# Expands \g{0}.
# Removes all remaining backslashes: in \( \| \) \\ ) but not in \[
# and \] and not inside [...].
# Returns list of John's rules
sub expand_0_john {
    map {
        # TODO: test this function with \0\0a\0\0b\0\0
        my @l = map { $_ eq '\\g{0}' ? '' : $_ }
            grep { $_ ne '' }
                split /(\\g\{0\})/;
        # warn ">> $_\n";
        # warn Dumper [@l];
        for (@l) {
            s/\\[][]|$bcc_re|\\([^g])|\\g/
                die "BUG: unexpanded back reference" if $& eq "\\g";
                defined $1 ? $1 : $&
             /ge;
        }
        local $_ = '';
        # If there is no \0 then we delete everything with x0z.
        my $zeros = int(grep { $_ eq '' } @l);
        # TODO: Don't screw current memorized value.
        # We don't use M if there is only one \0.
        $_ .= $zeros > 1 ? 'M ' : $zeros == 1 ? '' : "'1 ";
        my $f = shift @l;
        if ($f ne '') {
            $_ .= qq/A0"$f" /;
            shift @l if @l && $l[0] eq '';
        }
        $_ .= join " ", map { $_ eq '' ? "X0zz" : qq/Az"$_"/ } @l;
        # TODO: Is '1Az"..."\[ faster than current '1A0"..."\] ?
        s/\s+$//;
        $_ .= ' \]' if $zeros == 0;
        # TODO: Warn if user mixes $zeros == 0 with $zeros != 0 in one pack.
        $_
    } @_
}

# List of String -> List of Strings
# Returns list of John's rules
sub expand_to_john {
    $skipped = 0;
    my @r = map {
        my @variants = check_parity [to_tokens $token_re, $_];
        # warn Dumper [@variants];
        for (\&expand_quantifiers, \&join_tokens) {
            @variants = &$_(@variants);
            # warn svref_2object($_)->GV->NAME;
            # warn Dumper [@variants];
        }
        # warn "expand_0 expand_parenthesis";
        "# rexgen2rules.pl: $_", map {
            expand_0_john expand_parenthesis @$_
        } @variants
    } @_;
    if ($skipped) {
        warn "WARNING: We skipped $skipped variant(s) in rule $_[0] due to undefined back references\n";
    }
    @r
}

######################################################################
# Interface to John the Ripper

# TODO: Make an option to call `john -pipe -ru=temp -stdout` against
# supplied words with current rules as temporary.

######################################################################
# Testing part

# TODO: Make tests

######################################################################
# CLI / UI part

my $rule = "";
# $rule = '\0([123]|[oO]ne|[tT](wo|hree))';
# $rule = '\0(1|[oO]no|ONE)(2|[tT]wo|TWO)(3|[tT]hree|THREE)';
# $rule = '\0(1|[oO]no\0|ONE)(2|[tT]wo|TWO)(3|[tT]hree|THREE\0)';
# $rule = '(A|B)(1|2)';
# $rule = 'asdf\0qwer';
# $rule = 'b(\|a)(0|1)e';
# $rule = '<(a|b)>hi<\1>';
# $rule = 'a{3}';
# $rule = 'a{2,3}';
# $rule = '(a(?:\1|b)){2}';
# $rule = '\g2';
# $rule = '(a|(b|c))\3';
# $rule = '(a|(b|c))\2';

sub out {
    for (expand_to_john $_[0]) {
        print "$_\n";
    }
}

# Use this to double back slashes.
# perl -pe 's/\\/\\\\/g;'

# To generate examples:
# TODO: With 2>&1 all warnings are at the beginning.
# perl -le '@a = (q#asdf !a(b|c)\10! !<(b|i)>\0</\\1>!#, q#!\0END! !\0\0asdf\0\0qwer\0\0!#, q#!(a(?:\1|b)){2}! !(a|(b|c))\2!#); for (@a) { s/!/'"'"'/g; print q{\$ $0 } . $_; system qq{perl rexgen2rules.pl $_ 2>&1}; print "" }' | perl -pe 's/\\/\\\\/g; s/^\\\\\$/\\\$/'

my $doc = <<EOT;
Copyright © 2014 Aleksey Cherepanov <aleksey.4erepanov\@gmail.com>

Support subset of PCRE:
[123&(a-z...] Bracketed Character class,
re1|re2       Alternative
a{n,m}        Quantifier
a{n}  -> a{n,n}
a?    -> a{0,1}
\\0            Reference to the original word
\\g{0} -> \\0
\\g0   -> \\0
(re)          Capturing group
(?:re)        Not capturing group
\\1 - \\9       Back references to capturing groups
\\g{n}         Back refs like \\1 - \\9, n is any non-negative number
\\gN   -> \\g{N}
\\C            Just C if C is not a digit or 'g'

Incompatibilities with original rexgen:
- prints JtR's rules instead of generated candidates,
- does not support case insensitive mode,
- has \\g{} and \\g ,
- has (?: ) ,
- back references may work differently,
- ... and other subtle moments.

Incompatibilities with PCRE:
- \\01 is not an octal code,
- \\10 is \\g{1} and 0, not \\g{10}.
- no named groups (\\k will be active),
- no relative back refs (like \\g{-2}),
- no infinite quantifiers (*+) and no recursion.
- ... and many other features are missed.

Subjects to change in future versions:
- \\01 is \\0 and 1 currently. It may be changed. Use \\g{0}1 for explicit
separation.
- Named groups and in-group case-insensibility specification could be added.
- Command line options may be changed.

Examples:

\$ $0 asdf 'a(b|c)\\10' '<(b|i)>\\0</\\1>'
# rexgen2rules.pl: asdf
'1 A0"asdf" \\]
# rexgen2rules.pl: a(b|c)\\10
'1 A0"abb0" \\]
'1 A0"acc0" \\]
# rexgen2rules.pl: <(b|i)>\\0</\\1>
A0"<b>" Az"</b>"
A0"<i>" Az"</i>"

\$ $0 '\\0END' '\\0\\0asdf\\0\\0qwer\\0\\0'
# rexgen2rules.pl: \\0END
Az"END"
# rexgen2rules.pl: \\0\\0asdf\\0\\0qwer\\0\\0
M X0zz Az"asdf" X0zz X0zz Az"qwer" X0zz X0zz

\$ $0 '(a(?:\\1|b)){2}' '(a|(b|c))\\2'
WARNING: We skipped 1 variant(s) in rule (a(?:\\1|b)){2} due to undefined back references
# rexgen2rules.pl: (a(?:\\1|b)){2}
'1 A0"abaab" \\]
'1 A0"abab" \\]
WARNING: We skipped 1 variant(s) in rule (a|(b|c))\\2 due to undefined back references
# rexgen2rules.pl: (a|(b|c))\\2
'1 A0"bb" \\]
'1 A0"cc" \\]

\$ (echo; echo '[List.Rules:my]'; perl $0 '(a(?:\\1|b)){2}' '(a|(b|c))\\2') >> ./JohnTheRipper/run/john.conf
...
\$ echo asdf | ./JohnTheRipper/run/john -pipe -ru=my -stdout
Press 'q' or Ctrl-C to abort, almost any other key for status
abaab
abab
bb
cc
4p 0:00:00:00 40.00p/s cc

Bugs:
If you combine generated rules with hand-written and you use more than
one reference to the original word then you should be careful about
john's M rule because $0 emits M rule itself.

This version is a draft yet. May be buggy. Please report problems
onto john-users\@lists.openwall.com mailing list. Thanks!

\\/ \\/ \\/ \\/ \\/ \\/ \\/ \\/ \\/ \\/ \\/ \\/
$0, version 0.1.
$0 converts rexgen-like rules into rules
for John the Ripper and prints the result to stdout.
Usage: $0 rule1 [rule2 ...]
EOT

if ($rule) {
    out $rule;
} else {
    die "$doc" unless @ARGV;
    for $rule (@ARGV) {
        out $rule;
    }
}
