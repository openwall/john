#!/bin/sh
#
##############################################################################
# tests dynamic_compiler code against legacy dynamic_# hashes, pulling data
# from dynamic_# using --list=format-tests.
#
# usage:
#    ./dyna-compile-tst.sh           (runs 'full' test)
#    ./dyna-compile-tst.sh  SHOW     (runs in 'show' mode, showing output)
#    ./dyna-compile-tst.sh  # expr   (runs a single test for dyna_# with expr)
##############################################################################

typeset -i GOOD
typeset -i FAIL
GOOD=0
FAIL=0

function do_test()
{
  ../run/john --list=format-tests --format=dynamic_$1 | cut -f 3 > dct-in
  ../run/john --list=format-tests --format=dynamic_$1 | cut -f 4 > dct-in.dic
  if [ "x$3" = "xSHOW" ]
  then
    ../run/john dct-in -w=dct-in.dic -format=dynamic="$2"
  else
    ../run/john dct-in -w=dct-in.dic -format=dynamic="$2" > /dev/null 2>&1
    VAL=`../run/john dct-in -w=dct-in.dic -format=dynamic="$2" 2> /dev/null | tail -1`
    if [ "x$VAL" != 'xNo password hashes left to crack (see FAQ)' ]
    then
      echo "FAILURE!!! $1 -> $2"
      let FAIL=$FAIL+1
    else
      echo "Success    $1 -> $2"
      let GOOD=$GOOD+1
    fi
  fi
  rm -f dct-in dct-in.dic
}

function large_hash_set()
{
  typeset -i NUM
  NUM=$1         ; do_test $NUM   "$2(\$p)"                $3
  let NUM=$NUM+1 ; do_test $NUM   "$2(\$s.\$p)"            $3
  let NUM=$NUM+1 ; do_test $NUM   "$2(\$p.\$s)"            $3
  let NUM=$NUM+1 ; do_test $NUM   "$2($2(\$p))"            $3
  let NUM=$NUM+1 ; do_test $NUM   "$2(${2}_raw(\$p))"      $3
  let NUM=$NUM+1 ; do_test $NUM   "$2($2(\$p).\$s)"        $3
  let NUM=$NUM+1 ; do_test $NUM   "$2(\$s.$2(\$p))"        $3
  if [ $NUM = 86 ] ; then return ; fi
  let NUM=$NUM+1 ; do_test $NUM   "$2($2(\$s).$2(\$p))"    $3
  let NUM=$NUM+1 ; do_test $NUM   "$2($2(\$p).$2(\$p))"    $3
}

if [ "x$2" != "x" ]
then
  do_test $1 $2 SHOW
  exit 1
fi

do_test 0 'md5($p)'                          $1
do_test 1 'md5($p.$s)'                       $1
do_test 2 'md5(md5($p))'                     $1
do_test 3 'md5(md5(md5($p)))'                $1
do_test 4 'md5($s.$p)'                       $1
do_test 5 'md5($s.$p.$s)'                    $1
do_test 6 'md5(md5($p).$s)'                  $1
do_test 8 'md5(md5($s).$p)'                  $1
do_test 9 'md5($s.md5($p))'                  $1
do_test 10 'md5($s.md5($s.$p))'              $1
do_test 11 'md5($s.md5($p.$s))'              $1
do_test 12 'md5(md5($s).md5($p))'            $1
do_test 13 'md5(md5($p).md5($s))'            $1
do_test 14 'md5($s.md5($p).$s)'              $1
do_test 15 'md5($u.md5($p).$s)'              $1
do_test 16 'md5(md5(md5($p).$s).$s2)'        $1
do_test 22 'md5(sha1($p))'                   $1
do_test 23 'sha1(md5($p))'                   $1
do_test 24 'sha1($p.$s)'                     $1
do_test 25 'sha1($s.$p)'                     $1
do_test 26 'sha1($p)'                        $1
do_test 29 'md5(utf16($p))'                  $1
do_test 30 'md4($p)'                         $1
do_test 31 'md4($s.$p)'                      $1
do_test 32 'md4($p.$s)'                      $1
do_test 33 'md4(utf16($p))'                  $1
do_test 34 'md5(md4($p))'                    $1
do_test 35 'sha1(uc($u).$c1.$p),c1=\x3a'     $1
do_test 36 'sha1($u.$c1.$p),c1=\x3a'         $1
do_test 37 'sha1(lc($u).$p)'                 $1
do_test 38 'sha1($s.sha1($s.sha1($p)))'      $1
do_test 39 'md5($s.pad16($p)),saltlen=-231'  $1
do_test 40 'sha1($s.pad20($p)),saltlen=-227' $1

large_hash_set 50 sha224         $1
large_hash_set 60 sha256         $1
large_hash_set 70 sha384         $1
large_hash_set 80 sha512         $1
large_hash_set 90 gost           $1
large_hash_set 100 whirlpool     $1
large_hash_set 110 tiger         $1
large_hash_set 120 ripemd128     $1
large_hash_set 130 ripemd160     $1
large_hash_set 140 ripemd256     $1
large_hash_set 150 ripemd320     $1
large_hash_set 160 haval128_3    $1
large_hash_set 170 haval128_4    $1
large_hash_set 180 haval128_5    $1
large_hash_set 190 haval160_3    $1
large_hash_set 200 haval160_4    $1
large_hash_set 210 haval160_5    $1
large_hash_set 220 haval192_3    $1
large_hash_set 230 haval192_4    $1
large_hash_set 240 haval192_5    $1
large_hash_set 250 haval224_3    $1
large_hash_set 260 haval224_4    $1
large_hash_set 270 haval224_5    $1
large_hash_set 280 haval256_3    $1
large_hash_set 290 haval256_4    $1
large_hash_set 300 haval256_5    $1
large_hash_set 310 md2           $1
large_hash_set 320 panama        $1
large_hash_set 330 skein224      $1
large_hash_set 340 skein256      $1
large_hash_set 350 skein384      $1
large_hash_set 360 skein512      $1

echo ""
if [ $FAIL -eq 0 ] ; then echo -n "ALL tests successful. " ; else echo "THERE WERE $FAIL FAILURES!" ; fi
echo "There were $GOOD tests completed"
echo ""

exit $FAIL
