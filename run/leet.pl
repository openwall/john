#! /usr/bin/env perl -l
# John rules generator for combination of 1337-speak substitutions.
# Proof of concept

# Copyright © 2014 Aleksey Cherepanov <aleksey.4erepanov@gmail.com>
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

use strict;
use warnings;

use Data::Dumper;

# TODO: Do we need to replace letter with itself? I guess, no.
my %replacements = qw/s [S5$] e [E3]/;
# Each letter could be replaced in $max_count places
my $max_count = 2;
# Try positions up to $max_pos position
my $max_pos = 5;

my @letters = keys %replacements;
my @letters_counts = (0) x @letters;

sub generate_positions {
    my $c = shift;
    return [] if $c == 0;
    my $mp = shift;
    my @r;
    for my $p ($c .. $mp) {
        my @t = generate_positions($c - 1, $p - 1);
        push @$_, $p for @t;
        push @r, @t;
    }
    @r
}

# warn Dumper [generate_positions 2, 4];

# TODO: We don't replace all. Do that separately.

sub combine {
    my $a = shift;
    my $b = shift;
    # warn Dumper $a, $b;
    my @r;
    # return @$a unless @$b;
    for my $i (@$a) {
        for my $j (@$b) {
            push @r, [@$i, $j];
        }
    }
    @r
}

while (1) {
    # Print variants for given counts
    my @rules = [];
    # warn Dumper [@letters_counts];
    for (0 .. $#letters) {
        my $letter = $letters[$_];
        my $replacement = $replacements{$letter};
        my $count = $letters_counts[$_];
        my @letter_rules;
        if ($count > 0) {
            my @positions = generate_positions($count, $max_pos);
            # warn Dumper [$count, $max_pos, @positions];
            for (@positions) {
                # We use positions in back order so first replacement
                # does not change numbers of others.
                # TODO: We may exploit change and simplify rules:
                # %2s op[S5$] %1s op[S5$]  ->  %1s op[S5$] %1s op[S5$]
                push @letter_rules, join " ", map {
                    "%$_$letter op$replacement"
                } reverse @$_;
            }
            @rules = combine [@rules], [@letter_rules];
        }
    }
    # warn Dumper [@rules];
    for (@rules) {
        if ($#$_ == -1) {
            print ":"
        } else {
            print join " ", @$_;
        }
    }
    # Increase counts like: 0,0,0 -> 0,0,1 -> 0,0,2 -> 0,1,0
    $letters_counts[$#letters_counts]++;
    my $i = $#letters_counts;
    for (; $i > 0 && $letters_counts[$i] > $max_count; $i--) {
        $letters_counts[$i] = 0;
        $letters_counts[$i - 1]++;
    }
    last if $i == 0 && $letters_counts[$i] > $max_count;
}
