#!/usr/bin/env perl
#------------------------------------------------------------------------------
# File:         exiftool
#
# Description:  Read/write meta information
#
# Revisions:    Nov. 12/03 - P. Harvey Created
#               (See html/history.html for revision history)
#
# References:   ATV - Alexander Vonk, private communication
#------------------------------------------------------------------------------
#
# Copyright 2003-2017, Phil Harvey
#
# This is free software; you can redistribute it and/or modify it under the
# same terms as Perl itself.
#
# "pdf2john.pl" was glued together by Dhiru Kholia.

use warnings;
use strict;
require 5.004;

my $version = '8.99';

# add our 'lib' directory to the include list BEFORE 'use ExifTool'
use Cwd qw(realpath);
my $exeDir;
BEGIN {
    # get exe directory
    $exeDir = (realpath($0) =~ /(.*)[\\\/]/) ? $1 : '.';
    # add lib directory at start of include path
    unshift @INC, "$exeDir/lib";
    # load or disable config file if specified
    if (@ARGV and lc($ARGV[0]) eq '-config') {
        shift;
        $ExifTool::configFile = shift;
    }
}
use ExifTool qw{:Public Open};

# function prototypes
sub SigInt();
sub SigCont();
sub Cleanup();
sub GetImageInfo($$);
sub SetImageInfo($$$);
sub CleanXML($);
sub EncodeXML($);
sub FormatXML($$$);
sub EscapeJSON($;$);
sub FormatJSON($$$);
sub PrintCSV();
sub ConvertBinary($);
sub AddSetTagsFile($;$);
sub DoSetFromFile($$$);
sub CleanFilename($);
sub ProcessFiles($;$);
sub ScanDir($$;$);
sub PreserveTime();
sub LoadPrintFormat($);
sub FilenameSPrintf($;$);
sub NextUnusedFilename($;$);
sub CreateDirectory($);
sub OpenOutputFile($);
sub AcceptFile($);
sub SlurpFile($$);
sub Rename($$);
sub ReadStayOpen($);
sub PrintTagList($@);
sub PrintErrors($$$);

$SIG{INT}  = 'SigInt';  # do cleanup on Ctrl-C
$SIG{CONT} = 'SigCont'; # (allows break-out of delays)
END {
    Cleanup();
}

# declare all static file-scope variables
my @commonArgs;     # arguments common to all commands
my @csvFiles;       # list of files when reading with CSV option
my @csvTags;        # order of tags for first file with CSV option (lower case)
my @delFiles;       # list of files to delete
my @dynamicFiles;   # list of -tagsFromFile files with dynamic names and -TAG<=FMT pairs
my @exclude;        # list of excluded tags
my @files;          # list of files and directories to scan
my @moreArgs;       # more arguments to process after -stay_open -@
my @newValues;      # list of new tag values to set
my @srcFmt;         # source file name format strings
my @tags;           # list of tags to extract
my %csvTags;        # lookup for all found tags with CSV option (lower case keys)
my %database;       # lookup for database information based on file name
my %filterExt;      # lookup for filtered extensions
my %ignore;         # directory names to ignore
my %preserveTime;   # preserved timestamps for files
my %printFmt;       # the contents of the print format file
my %setTags;        # hash of list references for tags to set from files
my %setTagsList;    # list of other tag lists for multiple -tagsFromFile from the same file
my %warnedOnce;     # lookup for once-only warnings
my $allGroup;       # show group name for all tags
my $argFormat;      # use exiftool argument-format output
my $binaryOutput;   # flag for binary output (undef or 1, or 0 for binary XML/PHP)
my $binaryStdout;   # flag set if we output binary to stdout
my $comma;          # flag set if we need a comma in JSON output
my $condition;      # conditional processing of files
my $count;          # count of files scanned
my $countBad;       # count of files with errors
my $countBadCr;     # count files not created due to errors
my $countBadWr;     # count write errors
my $countCopyWr;    # count of files copied without being changed
my $countCreated;   # count output files created
my $countDir;       # count of directories scanned
my $countFailed;    # count files that failed condition
my $countGoodCr;    # count files created OK
my $countGoodWr;    # count files written OK
my $countNewDir;    # count of directories created
my $countSameWr;    # count files written OK but not changed
my $critical;       # flag for critical operations (disable CTRL-C)
my $csv;            # flag for CSV option (set to "CSV", or maybe "JSON" when writing)
my $csvAdd;         # flag to add CSV information to existing lists
my $csvSaveCount;   # save counter for last CSV file loaded
my $deleteOrig;     # 0=restore original files, 1=delete originals, 2=delete w/o asking
my $disableOutput;  # flag to disable normal output
my $doSetFileName;  # flag set if FileName may be written
my $doUnzip;        # flag to extract info from .gz and .bz2 files
my $escapeHTML;     # flag to escape printed values for html
my $evalWarning;    # warning from eval
my $executeID;      # -execute ID number
my $fileHeader;     # header to print to output file (or console, once)
my $fileTrailer;    # trailer for output file
my $filtered;       # flag indicating file was filtered by name
my $filterFlag;     # file filter flag (0x01=deny extensions, 0x02=allow extensions)
my $fixLen;         # flag to fix description lengths when writing alternate languages
my $forcePrint;     # force printing of tags whose values weren't found
my $helped;         # flag to avoid printing help if no tags specified
my $html;           # flag for html-formatted output (2=html dump)
my $interrupted;    # flag set if CTRL-C is pressed during a critical process
my $isWriting;      # flag set if we are writing tags
my $joinLists;      # flag set to join list values into a single string
my $json;           # flag for JSON/PHP output format (1=JSON, 2=PHP)
my $listItem;       # item number for extracting single item from a list
my $listSep;        # list item separator (', ' by default)
my $mainTool;       # main ExifTool object
my $multiFile;      # non-zero if we are scanning multiple files
my $outFormat;      # -1=Canon format, 0=same-line, 1=tag names, 2=values only
my $outOpt;         # output file or directory name
my $overwriteOrig;  # flag to overwrite original file
my $pause;          # pause before returning
my $preserveTime;   # flag to preserve times of updated files
my $progress;       # progress cound
my $progressMax;    # total number of files to process
my $progStr;        # progress message string
my $quiet;          # flag to disable printing of informational messages / warnings
my $recurse;        # recurse into subdirectories
my $rtnVal;         # command return value (0=success)
my $saveCount;      # count the number of times we will/did call SaveNewValues()
my $scanWritable;   # flag to process only writable file types
my $seqFileNum;     # sequential file number used for %C
my $showGroup;      # number of group to show (may be zero or '')
my $showTagID;      # non-zero to show tag ID's
my $stayOpenBuff='';# buffer for -stay_open file
my $stayOpenFile;   # name of the current -stay_open argfile
my $structOpt;      # output structured XMP information (JSON and XML output only)
my $tabFormat;      # non-zero for tab output format
my $textOut;        # extension for text output file (or undef for no output)
my $textOverwrite;  # flag to overwrite existing text output file
my $tmpFile;        # temporary file to delete on exit
my $tmpText;        # temporary text file
my $utf8;           # flag set if we are using UTF-8 encoding
my $validFile;      # flag indicating we processed a valid file
my $verbose;        # verbose setting
my $xml;            # flag for XML-formatted output

# flag to keep the input -@ argfile open:
# 0 = normal behaviour
# 1 = received "-stay_open true" and waiting for argfile to keep open
# 2 = currently reading from STAYOPEN argfile
# 3 = waiting for -@ to switch to a new STAYOPEN argfile
my $stayOpen = 0;

# lookup for O/S names which may use a backslash as a directory separator
# (ref File::Spec of PathTools-3.2701)
my %hasBackslash = ( MSWin32 => 1, os2 => 1, dos => 1, NetWare => 1, symbian => 1, cygwin => 1 );

# lookup for O/S names which use CR/LF newlines
my $isCRLF = { MSWin32 => 1, os2 => 1, dos => 1 }->{$^O};

# lookup for JSON characters that we escape specially
my %jsonChar = ( '"'=>'"', '\\'=>'\\', "\t"=>'t', "\n"=>'n', "\r"=>'r' );

# options requiring additional arguments
# (used only to skip over these arguments when reading -stay_open ARGFILE)
my %optArgs = (
    '-tagsfromfile' => 1, '-addtagsfromfile' => 1, '-alltagsfromfile' => 1,
    '-@' => 1,
    '-c' => 1, '-coordformat' => 1,
    '-charset' => 0, # (optional arg; OK because arg cannot begin with "-")
    '-config' => 1,
    '-d' => 1, '-dateformat' => 1,
    '-D' => 0, # nececessary to avoid matching lower-case equivalent
    '-echo' => 1, '-echo2' => 1,
    '-ext' => 1, '--ext' => 1, '-extension' => 1, '--extension' => 1,
    '-fileorder' => 1,
    '-geotag' => 1,
    '-i' => 1, '-ignore' => 1,
    '-if' => 1,
    '-lang' => 0, # (optional arg; cannot begin with "-")
    '-listitem' => 1,
    '-o' => 1, '-out' => 1,
    '-p' => 1, '-printformat' => 1,
    '-P' => 0,
    '-password' => 1,
    '-require' => 1,
    '-sep' => 1, '-separator' => 1,
    '-srcfile' => 1,
    '-stay_open' => 1,
    '-use' => 1,
    '-w' => 1, '-w!' => 1, '-textout' => 1, '-textout!' => 1,
    '-x' => 1, '-exclude' => 1,
    '-X' => 0,
);

# exit routine
sub Exit {
    if ($pause) {
        if (eval 'require Term::ReadKey') {
            print STDERR "-- press any key --";
            Term::ReadKey::ReadMode('cbreak');
            Term::ReadKey::ReadKey(0);
            Term::ReadKey::ReadMode(0);
            print STDERR "\b \b" x 20;
        } else {
            print STDERR "-- press RETURN --\n";
            <STDIN>;
        }
    }
    exit shift;
}
# my warning and error routines (NEVER say "die"!)
sub Warn  { warn(@_) if $quiet < 2 or $_[0] =~ /^Error/; }
sub Error { Warn @_; $rtnVal = 1; }
sub WarnOnce($) {
    Warn(@_) and $warnedOnce{$_[0]} = 1 unless $warnedOnce{$_[0]};
}

# define signal handlers and cleanup routine
sub SigInt()  {
    $critical and $interrupted = 1, return;
    Cleanup();
    exit 1;
}
sub SigCont() { }
sub Cleanup() {
    unlink $tmpFile if defined $tmpFile;
    unlink $tmpText if defined $tmpText;
    undef $tmpFile;
    undef $tmpText;
    PreserveTime() if %preserveTime;
}

#------------------------------------------------------------------------------
# main script
#

# isolate arguments common to all commands
if (grep /^-common_args$/i, @ARGV) {
    my (@newArgs, $common);
    foreach (@ARGV) {
        if (/^-common_args$/i) {
            $common = 1;
        } elsif ($common) {
            push @commonArgs, $_;
        } else {
            push @newArgs, $_;
        }
    }
    @ARGV = @newArgs if $common;
}

#..............................................................................
# loop over sets of command-line arguments separated by "-execute"
Command: while (@ARGV or not defined $rtnVal or $stayOpen >= 2 or @commonArgs)
{

# attempt to restore text mode for STDOUT if necessary
if ($binaryStdout) {
    binmode(STDOUT,':crlf') if $] >= 5.006 and $isCRLF;
    $binaryStdout = 0;
}

# flush console and print "{ready}" message if -stay_open is in effect
if ($stayOpen >= 2 and not $quiet) {
    eval 'require IO::Handle' and STDERR->flush();
    my $id = defined $executeID ? $executeID : '';
    my $save = $|;
    $| = 1;     # turn on output autoflush for stdout
    print "{ready$id}\n";
    $| = $save; # restore original autoflush setting
}

$rtnVal = 0 unless defined $rtnVal;

# initialize necessary static file-scope variables
# (not done: @commonArgs, @moreArgs, $critical, $binaryStdout, $helped,
#  $interrupted, $mainTool, $pause, $rtnVal, $stayOpen, $stayOpenBuff, $stayOpenFile)
undef @dynamicFiles;
undef @exclude;
undef @files;
undef @newValues;
undef @srcFmt;
undef @tags;
undef %database;
undef %filterExt;
undef %ignore;
undef %printFmt;
undef %preserveTime;
undef %setTags;
undef %setTagsList;
undef %warnedOnce;
undef $allGroup;
undef $argFormat;
undef $binaryOutput;
undef $comma;
undef $condition;
undef $deleteOrig;
undef $disableOutput;
undef $doSetFileName;
undef $escapeHTML;
undef $evalWarning;
undef $executeID;
undef $fileHeader;
undef $fileTrailer;
undef $filtered;
undef $fixLen;
undef $forcePrint;
undef $joinLists;
undef $listItem;
undef $multiFile;
undef $outOpt;
undef $preserveTime;
undef $progress;
undef $progressMax;
undef $recurse;
undef $scanWritable;
undef $showGroup;
undef $showTagID;
undef $structOpt;
undef $textOut;
undef $textOverwrite;
undef $tmpFile;
undef $tmpText;
undef $validFile;
undef $verbose;

$count = 0;
$countBad = 0;
$countBadCr = 0;
$countBadWr = 0;
$countCopyWr = 0;
$countCreated = 0;
$countDir = 0;
$countFailed = 0;
$countGoodCr = 0;
$countGoodWr = 0;
$countNewDir = 0;
$countSameWr = 0;
$csvSaveCount = 0;
$filterFlag = 0;
$html = 0;
$isWriting = 0;
$json = 0;
$listSep = ', ';
$outFormat = 0;
$overwriteOrig = 0;
$progStr = '';
$quiet = 0;
$saveCount = 0;
$seqFileNum = 0;
$tabFormat = 0;
$utf8 = 1;
$xml = 0;

# define local variables used only in this command loop
my @fileOrder;      # tags to use for ordering of input files
my %excludeGrp;     # hash of tags excluded by group
my $addGeotime;     # automatically added geotime argument
my $allInGroup;     # flag to show all tags in a group
my $doGlob;         # flag set to do filename wildcard expansion
my $escapeXML;      # flag to escape printed values for xml
my $setTagsFile;    # filename for last TagsFromFile option
my $sortOpt;        # sort option is used
my $useMWG;         # flag set if we are using any MWG tag

my ($argsLeft, @nextPass);
my $pass = 0;

# for Windows, use globbing for wildcard expansion if available - MK/20061010
if ($^O eq 'MSWin32' and eval 'require File::Glob') {
    # override the core glob forcing case insensitivity
    import File::Glob qw(:globally :nocase);
    $doGlob = 1;
}

$mainTool = new ExifTool;        # create ExifTool object

# don't extract duplicates by default unless set by UserDefined::Options
$mainTool->Options(Duplicates => 0) unless %ExifTool::UserDefined::Options
    and defined $ExifTool::UserDefined::Options{Duplicates};

# parse command-line options in 2 passes...
# pass 1: set all of our ExifTool options
# pass 2: print all of our help and informational output (-list, -ver, etc)
for (;;) {

  # execute the command now if no more arguments or -execute is used
  if (not @ARGV or $ARGV[0] =~ /^-execute(\d*)$/i) {
    if (@ARGV) {
        $executeID = $1;        # save -execute number for "{ready}" response
        $helped = 1;            # don't show help if we used -execute
    } elsif ($stayOpen >= 2) {
        ReadStayOpen(\@ARGV);   # read more arguments from -stay_open file
        next;
    }
    if ($pass == 0) {
        # insert common arguments now if not done already
        if (@commonArgs and not defined $argsLeft) {
            # count the number of arguments remaining for subsequent commands
            $argsLeft = scalar(@ARGV) + scalar(@moreArgs);
            unshift @ARGV, @commonArgs;
            # all done with commonArgs if this is the end of the command
            undef @commonArgs unless $argsLeft;
            next;
        }
        # check if we have more arguments now than we did before we processed
        # the common arguments.  If so, then we have an infinite processing loop
        if (defined $argsLeft and $argsLeft < scalar(@ARGV) + scalar(@moreArgs)) {
            Warn "Ignoring -common_args from $ARGV[0] onwards to avoid infinite recursion\n";
            while ($argsLeft < scalar(@ARGV) + scalar(@moreArgs)) {
                @ARGV and shift(@ARGV), next;
                shift @moreArgs;
            }
        }
        # require MWG module if used in any argument
        # (note: this also covers the -p option because these tags were added to @tags)
        $useMWG = 1 if not $useMWG and grep /^mwg:/i, @tags;
        require ExifTool::MWG if $useMWG;
    }
    if (@nextPass) {
        # process arguments which were deferred to the next pass
        unshift @ARGV, @nextPass;
        undef @nextPass;
        ++$pass;
        next;
    }
    @ARGV and shift;    # remove -execute from argument list
    last;               # process the command now
  }
  $_ = shift;
  if (s/^(-|\xe2\x88\x92)//) {  # allow funny dashes (nroff dash bug for cut-n-paste from pod)
    s/^\xe2\x88\x92/-/;         # translate double-dash too
    my $a = lc $_;
    if (/^list([wfrdx]|wf|g(\d*))?$/i) {
        $pass or push(@nextPass,"-$_");
        my $type = lc($1 || '');
        if (not $type or $type eq 'w' or $type eq 'x') {
            my $group;
            if ($ARGV[0] and $ARGV[0] =~ /^(-|\xe2\x88\x92)(.+):(all|\*)$/i) {
                if ($pass == 0) {
                    $useMWG = 1 if lc($2) eq 'mwg';
                    push(@nextPass, shift);
                    next;
                }
                $group = $2;
                shift;
                $group =~ /IFD/i and Warn("Can't list tags for specific IFD\n"), next;
                $group =~ /^(all|\*)$/ and undef $group;
            } else {
                $pass or next;
            }
            $helped = 1;
            if ($type eq 'x') {
                require ExifTool::TagInfoXML;
                my %opts;
                $opts{Flags} = 1 if $forcePrint;
                $opts{NoDesc} = 1 if $outFormat > 0;
                ExifTool::TagInfoXML::Write(undef, $group, %opts);
                next;
            }
            my $wr = ($type eq 'w');
            my $msg = ($wr ? 'Writable' : 'Available') . ($group ? " $group" : '') . ' tags';
            PrintTagList($msg, $wr ? GetWritableTags($group) : GetAllTags($group));
            # also print shortcuts if listing all tags
            next if $group or $wr;
            my @tagList = GetShortcuts();
            PrintTagList('Command-line shortcuts', @tagList) if @tagList;
            next;
        }
        $pass or next;
        $helped = 1;
        if ($type eq 'wf') {
            my @wf;
            CanWrite($_) and push @wf, $_ foreach GetFileType();
            PrintTagList('Writable file extensions', @wf);
        } elsif ($type eq 'f') {
            PrintTagList('Supported file extensions', GetFileType());
        } elsif ($type eq 'r') {
            PrintTagList('Recognized file extensions', GetFileType(undef, 0));
        } elsif ($type eq 'd') {
            PrintTagList('Deletable groups', GetDeleteGroups());
        } else { # 'g(\d*)'
            # list all groups in specified family
            my $family = $2 || 0;
            PrintTagList("Groups in family $family", GetAllGroups($family));
        }
        next;
    }
    if (/^(all|add)?tagsfromfile(=.*)?$/i) {
        $setTagsFile = $2 ? substr($2,1) : (@ARGV ? shift : '');
        if ($setTagsFile eq '') {
            Error("File must be specified for -tagsFromFile option\n");
            next Command;
        }
        # create necessary lists, etc for this new -tagsFromFile file
        AddSetTagsFile($setTagsFile, { Replace => ($1 and lc($1) eq 'add') ? 0 : 1 } );
        next;
    }
    if ($a eq '@') {
        my $argFile = shift or Error("Expecting filename for -\@ option\n"), next Command;
        # switch to new ARGFILE if using chained -stay_open options
        if ($stayOpen == 1) {
            # defer remaining arguments until we close this argfile
            @moreArgs = @ARGV;
            undef @ARGV;
        } elsif ($stayOpen == 3) {
            if ($stayOpenFile and $stayOpenFile ne '-' and $argFile eq $stayOpenFile) {
                # don't allow user to switch to the same -stay_open argfile
                # because it will result in endless recursion
                $stayOpen = 2;
                Warn "Ignoring request to switch to the same -stay_open ARGFILE ($argFile)\n";
                next;
            }
            close STAYOPEN;
            $stayOpen = 1;  # switch to this -stay_open file
        }
        my $fp = ($stayOpen == 1 ? \*STAYOPEN : \*ARGFILE);
        unless (Open($fp, $argFile)) {
            unless ($argFile !~ /^\// and Open($fp, "$exeDir/$argFile")) {
                Error "Error opening arg file $argFile\n";
                next Command;
            }
        }
        if ($stayOpen == 1) {
            $stayOpenFile = $argFile;   # remember the name of the file we have open
            $stayOpenBuff = '';         # initialize buffer for reading this file
            $stayOpen = 2;
            $helped = 1;
            ReadStayOpen(\@ARGV);
            next;
        }
        my (@newArgs, $didBOM);
        foreach (<ARGFILE>) {
            # filter Byte Order Mark if it exists from start of UTF-8 text file
            unless ($didBOM) {
                s/^\xef\xbb\xbf//;
                $didBOM = 1;
            }
            s/^\s+//; s/[\x0d\x0a]+$//s; # remove leading white space and trailing newline
            # remove white space before, and single space after '=', '+=', '-=' or '<='
            s/^(-[-:\w]+#?)\s*([-+<]?=) ?/$1$2/;
            push @newArgs, $_ unless $_ eq '' or /^#/;
        }
        close ARGFILE;
        unshift @ARGV, @newArgs;
        next;
    }
    /^(-?)(a|duplicates)$/i and $mainTool->Options(Duplicates => ($1 ? 0 : 1)), next;
    /^arg(s|format)$/i and $argFormat = 1, next;
    /^b(inary)?$/i and $mainTool->Options(Binary => 1), $binaryOutput = 1,  next;
    if (/^c(oordFormat)?$/i) {
        my $fmt = shift;
        $fmt or Error("Expecting coordinate format for -c option\n"), next Command;
        $mainTool->Options('CoordFormat', $fmt);
        next;
    }
    if ($a eq 'charset') {
        my $charset = (@ARGV and $ARGV[0] !~ /^(-|\xe2\x88\x92)/) ? shift : undef;
        if (not $charset) {
            $pass or push(@nextPass, '-charset'), next;
            my %charsets;
            $charsets{$_} = 1 foreach values %ExifTool::charsetName;
            PrintTagList('Available character sets', sort keys %charsets);
            $helped = 1;
        } elsif ($charset !~ s/^(\w+)=// or lc($1) eq 'exiftool') {
            $mainTool->Options(Charset => $charset);
            $utf8 = ($mainTool->Options('Charset') eq 'UTF8');
        } else {
            # set internal encoding of specified metadata type
            my $type = { id3 => 'ID3', iptc => 'IPTC', exif => 'EXIF',
                         photoshop => 'Photoshop', quicktime => 'QuickTime' }->{lc $1};
            $type or Warn("Unknown type for -charset option: $1\n"), next;
            $mainTool->Options("Charset$type" => $charset);
        }
        next;
    }
    /^config$/i and Warn("Ignored -config option (not first on command line)\n"), shift, next;
    if (/^csv(\+?=.*)?/i) {
        my $csvFile = $1;
        # must process on 2nd pass so -f option is available
        unless ($pass) {
            push(@nextPass,"-$_");
            if ($csvFile) {
                push @newValues, { SaveCount => ++$saveCount }; # marker to save new values now
                $csvSaveCount = $saveCount;
            }
            next;
        }
        if ($csvFile) {
            $csvFile =~ s/^(\+?=)//;
            $csvAdd = 2 if $1 eq '+=';
            $verbose and print "Reading CSV file $csvFile\n";
            require ExifTool::Import;
            my $msg = ExifTool::Import::ReadCSV($csvFile, \%database, $forcePrint);
            $msg and Warn("$msg\n");
            $isWriting = 1;
        }
        $csv = 'CSV';
        next;
    }
    if (/^d$/ or $a eq 'dateformat') {
        my $fmt = shift;
        $fmt or Error("Expecting date format for -d option\n"), next Command;
        $mainTool->Options('DateFormat', $fmt);
        next;
    }
    (/^D$/ or $a eq 'decimal') and $showTagID = 'D', next;
    /^delete_original(!?)$/i and $deleteOrig = ($1 ? 2 : 1), next;
    (/^e$/ or $a eq '-composite') and $mainTool->Options(Composite => 0), next;
    (/^-e$/ or $a eq 'composite') and $mainTool->Options(Composite => 1), next;
    (/^E$/ or $a eq 'escapehtml') and require ExifTool::HTML and $escapeHTML = 1, next;
    ($a eq 'ex' or $a eq 'escapexml') and $escapeXML = 1, next;
    if (/^echo(2)?$/i) {
        next unless @ARGV;
        $pass or push(@nextPass, "-$_", shift), next;
        print {$1 ? \*STDERR : \*STDOUT} shift, "\n";
        $helped = 1;
        next;
    }
    if (/^(ee|extractembedded)$/i) {
        $mainTool->Options(ExtractEmbedded => 1);
        $mainTool->Options(Duplicates => 1);
        next;
    }
    # (-execute handled at top of loop)
    if (/^-?ext(ension)?$/i) {
        my $ext = shift;
        defined $ext or Error("Expecting extension for -ext option\n"), next Command;
        $ext =~ s/^\.//;    # remove leading '.' if it exists
        my $flag = /^-/ ? 0 : 1;
        $filterFlag |= (0x01 << $flag);
        $filterExt{uc($ext)} = $flag;
        next;
    }
    if (/^f$/ or $a eq 'forceprint') {
        $forcePrint = 1;
        $mainTool->Options(MissingTagValue => '-');
        next;
    }
    if (/^F([-+]?\d*)$/ or /^fixbase([-+]?\d*)$/i) {
        $mainTool->Options(FixBase => $1);
        next;
    }
    if (/^fast(\d*)$/i) {
        $mainTool->Options(FastScan => (length $1 ? $1 : 1));
        next;
    }
    if ($a eq 'fileorder') {
        push @fileOrder, shift if @ARGV;
        next;
    }
    $a eq 'globaltimeshift' and $mainTool->Options(GlobalTimeShift => shift), next;
    if (/^(g)(roupHeadings|roupNames)?([\d:]*)$/i) {
        $showGroup = $3 || 0;
        $allGroup = ($2 ? lc($2) eq 'roupnames' : $1 eq 'G');
        $mainTool->Options(SavePath => 1) if $showGroup =~ /\b5\b/;
        next;
    }
    if ($a eq 'geotag') {
        my $trkfile = shift;
        $trkfile or Error("Expecting file name for -geotag option\n"), next Command;
        # allow wildcards in filename
        if ($trkfile =~ /[*?]/) {
            # CORE::glob() splits on white space, so use File::Glob if possible
            my @trks = eval('require File::Glob') ? File::Glob::bsd_glob($trkfile) : glob($trkfile);
            @trks or Error("No matching file found for -geotag option\n"), next Command;
            push @newValues, 'geotag='.shift(@trks) while @trks > 1;
            $trkfile = pop(@trks);
        }
        $_ = "geotag=$trkfile";
        # (fall through!)
    }
    if (/^h$/ or $a eq 'htmlformat') {
        require ExifTool::HTML;
        $html = $escapeHTML = 1;
        $json = $xml = 0;
        next;
    }
    (/^H$/ or $a eq 'hex') and $showTagID = 'H', next;
    if (/^htmldump([-+]?\d+)?$/i) {
        $verbose = ($verbose || 0) + 1;
        $html = 2;
        $mainTool->Options(HtmlDumpBase => $1) if defined $1;
        next;
    }
    if (/^i(gnore)?$/i) {
        my $dir = shift;
        defined $dir or Error("Expecting directory name for -i option\n"), next Command;
        $ignore{$dir} = 1;
        next;
    }
    if ($a eq 'if') {
        my $cond = shift;
        defined $cond or Error("Expecting expression for -if option\n"), next Command;
        $useMWG = 1 if $cond =~ /\$\{?mwg:/i;
        if (defined $condition) {
            $condition .= " and ($cond)";
        } else {
            $condition = "($cond)";
        }
        next;
    }
    if (/^j(son)?(\+?=.*)?$/i) {
        if ($2) {
            # must process on 2nd pass because we need -f and -charset options
            unless ($pass) {
                push(@nextPass,"-$_");
                push @newValues, { SaveCount => ++$saveCount }; # marker to save new values now
                $csvSaveCount = $saveCount;
                next;
            }
            my $jsonFile = $2;
            $jsonFile =~ s/^(\+?=)//;
            $csvAdd = 2 if $1 eq '+=';
            $verbose and print "Reading JSON file $jsonFile\n";
            my $chset = $mainTool->Options('Charset');
            require ExifTool::Import;
            my $msg = ExifTool::Import::ReadJSON($jsonFile, \%database, $forcePrint, $chset);
            $msg and Warn("$msg\n");
            $isWriting = 1;
            $csv = 'JSON';
        } else {
            $json = 1;
            $html = $xml = 0;
            $mainTool->Options(Duplicates => 1);
            require ExifTool::XMP;   # for FixUTF8()
        }
        next;
    }
    /^(k|pause)$/i and $pause = 1, next;
    (/^l$/ or $a eq 'long') and --$outFormat, next;
    (/^L$/ or $a eq 'latin') and $utf8 = 0, $mainTool->Options(Charset => 'Latin'), next;
    if ($a eq 'lang') {
        my $lang = (@ARGV and $ARGV[0] !~ /^-/) ? shift : undef;
        if ($lang) {
            # make lower case and use underline as a separator (ie. 'en_ca')
            $lang =~ tr/-A-Z/_a-z/;
            $mainTool->Options(Lang => $lang);
            next if $lang eq $mainTool->Options('Lang');
        } else {
            $pass or push(@nextPass, '-lang'), next;
        }
        my $langs = "Available languages:\n";
        $langs .= "  $_ - $ExifTool::langName{$_}\n" foreach @ExifTool::langs;
        $langs =~ tr/_/-/;  # display dashes instead of underlines in language codes
        $langs = $mainTool->Decode($langs, 'UTF8');
        $langs = ExifTool::HTML::EscapeHTML($langs) if $escapeHTML;
        $lang and Error("Invalid or unsupported language '$lang'.\n$langs"), next Command;
        print $langs;
        $helped = 1;
        next;
    }
    if ($a eq 'listitem') {
        $listItem = shift;
        defined $listItem or Warn("Expecting index for -listItem option\n");
        next;
    }
    /^(m|ignoreminorerrors)$/i and $mainTool->Options(IgnoreMinorErrors => 1), next;
    /^(n|-printconv)$/i and $mainTool->Options(PrintConv => 0), next;
    /^(-n|printconv)$/i and $mainTool->Options(PrintConv => 1), next;
    if (/^o(ut)?$/i) {
        $outOpt = shift;
        defined $outOpt or Error("Expected output file or directory name for -o option\n"), next Command;
        CleanFilename($outOpt);
        next;
    }
    /^overwrite_original$/i and $overwriteOrig = 1, next;
    /^overwrite_original_in_place$/i and $overwriteOrig = 2, next;
    (/^p$/ or $a eq 'printformat') and LoadPrintFormat(shift), next;
    (/^P$/ or $a eq 'preserve') and $preserveTime = 1, next;
    /^password$/i and $mainTool->Options(Password => shift), next;
    if ($a eq 'progress') {
        $progress = 0;
        $verbose = 0 unless defined $verbose;
        next;
    }
    /^q(uiet)?$/i and ++$quiet, next;
    /^r(ecurse)?$/i and $recurse = 1, next;
    if ($a eq 'require') { # undocumented, added in version 8.65
        my $ver = shift;
        unless (defined $ver and ExifTool::IsFloat($ver)) {
            Error("Expecting version number for -require option\n");
            next Command;
        }
        unless ($ExifTool::VERSION >= $ver) {
            Error("Requires ExifTool version $ver or later\n");
            next Command;
        }
        next;
    }
    /^restore_original$/i and $deleteOrig = 0, next;
    (/^S$/ or $a eq 'veryshort') and $outFormat+=2, next;
    /^s(hort)?(\d*)$/i and $outFormat = $2 eq '' ? $outFormat + 1 : $2, next;
    /^scanforxmp$/i and $mainTool->Options(ScanForXMP => 1), next;
    if (/^sep(arator)?$/i) {
        $listSep = shift;
        defined $listSep or Error("Expecting list item separator for -sep option\n"), next Command;
        $mainTool->Options(ListSep => $listSep);
        $joinLists = 1;
        # also split when writing values
        my $listSplit = quotemeta $listSep;
        # a space in the string matches zero or more whitespace characters
        $listSplit =~ s/(\\ )+/\\s\*/g;
        # but a single space alone matches one or more whitespace characters
        $listSplit = '\\s+' if $listSplit eq '\\s*';
        $mainTool->Options(ListSplit => $listSplit);
        next;
    }
    /^sort$/i and $sortOpt = 1, next;
    if ($a eq 'srcfile') {
        @ARGV or Warn("Expecting FMT for -srcfile option\n"), next;
        push @srcFmt, shift;
        next;
    }
    if ($a eq 'stay_open') {
        my $arg = shift;
        defined $arg or Warn("Expecting argument for -stay_open option\n"), next;
        if ($arg =~ /^(1|true)$/i) {
            if (not $stayOpen) {
                $stayOpen = 1;
            } elsif ($stayOpen == 2) {
                $stayOpen = 3;  # chained -stay_open options
            } else {
                Warn "-stay_open already active\n";
            }
        } elsif ($arg =~ /^(0|false)$/i) {
            if ($stayOpen >= 2) {
                # close -stay_open argfile and process arguments up to this point
                close STAYOPEN;
                push @ARGV, @moreArgs;
                undef @moreArgs;
            } elsif (not $stayOpen) {
                Warn("-stay_open wasn't active\n");
            }
            $stayOpen = 0;
        } else {
            Warn "Invalid argument for -stay_open\n";
        }
        next;
    }
    if (/^(-)?struct$/i) {
        $structOpt = $1 ? 0 : 1;
        $mainTool->Options(Struct => $structOpt);
        # require XMPStruct in case we need to serialize a structure
        require 'Image/ExifTool/XMPStruct.pl' if $structOpt;
        next;
    }
    /^t(ab)?$/  and $tabFormat = 1, next;
    if (/^T$/ or $a eq 'table') {
        $tabFormat = 1; $outFormat+=2; ++$quiet; $forcePrint = 1;
        $mainTool->Options(MissingTagValue => '-');
        next;
    }
    if (/^(u)(nknown(2)?)?$/i) {
        my $inc = ($3 or (not $2 and $1 eq 'U')) ? 2 : 1;
        $mainTool->Options(Unknown => $mainTool->Options('Unknown') + $inc);
        next;
    }
    if ($a eq 'use') {
        my $module = shift;
        $module or Error("Expecting module name for -use option\n"), next Command;
        lc $module eq 'mwg' and $useMWG = 1, next;
        local $SIG{'__WARN__'} = sub { $evalWarning = $_[0] };
        unless (eval "require ExifTool::$module" or
                eval "require $module" or
                eval "require '$module'")
        {
            delete $SIG{'__WARN__'};
            Error("Error using module $module\n");
            next Command;
        }
        next;
    }
    if (/^v(erbose)?(\d*)$/i) {
        $verbose = ($2 eq '') ? ($verbose || 0) + 1 : $2;
        next;
    }
    if (/^(w|textout)(!?)$/i) {
        $textOut = shift || Warn("Expecting output extension for -$_ option\n");
        $textOverwrite = $2;
        next;
    }
    if (/^x$/ or $a eq 'exclude') {
        my $tag = shift;
        defined $tag or Error("Expecting tag name for -x option\n"), next Command;
        $tag =~ s/\ball\b/\*/ig;    # replace 'all' with '*' in tag names
        if ($setTagsFile) {
            push @{$setTags{$setTagsFile}}, "-$tag";
        } else {
            push @exclude, $tag;
        }
        next;
    }
    (/^X$/ or $a eq 'xmlformat') and $xml = 1, $html = $json = 0, $mainTool->Options(Duplicates => 1), next;
    if (/^php$/i) {
        $json = 2;
        $html = $xml = 0;
        $mainTool->Options(Duplicates=>1);
        next;
    }
    /^z(ip)?$/i and $doUnzip = 1, $mainTool->Options(Compress => 1, Compact => 1), next;
    $_ eq '' and push(@files, '-'), next;   # read STDIN
    length $_ eq 1 and $_ ne '*' and Error("Unknown option -$_\n"), next Command;
    if (/^[^<]+(<?)=(.*)/s) {
        my $val = $2;
        if ($1 and length($val) and ($val eq '@' or not defined FilenameSPrintf($val))) {
            # save count of new values before a dynamic value
            push @newValues, { SaveCount => ++$saveCount };
        }
        push @newValues, $_;
        if (/^mwg:/i) {
            $useMWG = 1;
        } elsif (/^([-\w]+:)*(filename|directory)\b/i) {
            $doSetFileName = 1;
        } elsif (/^([-\w]+:)*(geotag|geotime)\b/i) {
            if (lc $2 eq 'geotag') {
                if ((not defined $addGeotime or $addGeotime) and length $val) {
                    $addGeotime = ($1 || '') . 'Geotime<DateTimeOriginal';
                }
            } else {
                $addGeotime = '';
            }
        }
    } else {
        # assume '-tagsFromFile @' if tags are being redirected
        # and -tagsFromFile hasn't already been specified
        AddSetTagsFile($setTagsFile = '@') if not $setTagsFile and /(<|>)/;
        if ($setTagsFile) {
            push @{$setTags{$setTagsFile}}, $_;
            if (/>/) {
                $useMWG = 1 if /^(.*>\s*)?mwg:/si;
                if (/\b(filename|directory)#?$/i) {
                    $doSetFileName = 1;
                } elsif (/\bgeotime#?$/i) {
                    $addGeotime = '';
                }
            } else {
                $useMWG = 1 if /^([^<]+<\s*(.*\$\{?)?)?mwg:/si;
                if (/^([-\w]+:)*(filename|directory)\b/i) {
                    $doSetFileName = 1;
                } elsif (/^([-\w]+:)*geotime\b/i) {
                    $addGeotime = '';
                }
            }
        } elsif (/^-(.*)/) {
            push @exclude, $1;
        } else {
            push @tags, $_;
        }
    }
  } elsif ($doGlob and /[*?]/) {
    # glob each filespec if necessary - MK/20061010
    push @files, File::Glob::bsd_glob($_);
    $doGlob = 2;
  } else {
    push @files, $_;
  }
}

# change default EXIF string encoding if MWG used
if ($useMWG and not defined $mainTool->Options('CharsetEXIF')) {
    $mainTool->Options(CharsetEXIF => 'UTF8');
}

# print help
unless ((@tags and not $outOpt) or @files or @newValues) {
    if ($doGlob and $doGlob == 2) {
        Warn "No matching files\n";
        $rtnVal = 1;
        next;
    }
    if ($outOpt) {
        Warn "Nothing to write\n";
        $rtnVal = 1;
        next;
    }
    unless ($helped) {
        # catch warnings if we have problems running perldoc
        local $SIG{'__WARN__'} = sub { $evalWarning = $_[0] };
        my $dummy = \*SAVEERR;  # avoid "used only once" warning
        unless ($^O eq 'os2') {
            open SAVEERR, ">&STDERR";
            open STDERR, '>/dev/null';
        }
        if (system('perldoc',$0)) {
            print "Syntax:  pdf2john.pl <.pdf file(s)>\n";
            # print "Consult the exiftool documentation for a full list of options.\n";
        }
        unless ($^O eq 'os2') {
            close STDERR;
            open STDERR, '>&SAVEERR';
        }
    }
    next;
}

# do sanity check on -delete_original and -restore_original
if (defined $deleteOrig and (@newValues or @tags)) {
    if (not @newValues) {
        my $verb = $deleteOrig ? 'deleting' : 'restoring from';
        Warn "Can't specify tags when $verb originals\n";
    } elsif ($deleteOrig) {
        Warn "Can't use -delete_original when writing.\n";
        Warn "Maybe you meant -overwrite_original ?\n";
    } else {
        Warn "It makes no sense to use -restore_original when writing\n";
    }
    $rtnVal = 1;
    next;
}

if ($overwriteOrig > 1 and $outOpt) {
    Warn "Can't overwrite in place when -o option is used\n";
    $rtnVal = 1;
    next;
}

if ($escapeHTML or $json) {
    # must be UTF8 for HTML conversion and JSON output
    $mainTool->Options(Charset => 'UTF8');
    # use Escape option to do our HTML escaping unless XML output
    $mainTool->Options(Escape => 'HTML') if $escapeHTML and not $xml;
} elsif ($escapeXML and not $xml) {
    $mainTool->Options(Escape => 'XML');
}

# set sort option
if ($sortOpt) {
    # (note that -csv sorts alphabetically by default anyway if more than 1 file)
    my $sort = ($outFormat > 0 or $xml or $json or $csv) ? 'Tag' : 'Descr';
    $mainTool->Options(Sort => $sort, Sort2 => $sort);
}

# set up for RDF/XML, JSON and PHP output formats
if ($xml) {
    require ExifTool::XMP;   # for EscapeXML()
    my $charset = $mainTool->Options('Charset');
    # standard XML encoding names for supported Charset settings
    # (ref http://www.iana.org/assignments/character-sets)
    my %encoding = (
        UTF8     => 'UTF-8',
        Latin    => 'windows-1252',
        Latin2   => 'windows-1250',
        Cyrillic => 'windows-1251',
        Greek    => 'windows-1253',
        Turkish  => 'windows-1254',
        Hebrew   => 'windows-1255',
        Arabic   => 'windows-1256',
        Baltic   => 'windows-1257',
        Vietnam  => 'windows-1258',
        MacRoman => 'macintosh',
    );
    # switch to UTF-8 if we don't have a standard encoding name
    unless ($encoding{$charset}) {
        $charset = 'UTF8';
        $mainTool->Options(Charset => $charset);
    }
    # set file header/trailer for XML output
    $fileHeader = "<?xml version='1.0' encoding='$encoding{$charset}'?>\n" .
                  "<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>\n";
    $fileTrailer = "</rdf:RDF>\n";
    # extract as a list unless short output format
    $joinLists = 1 if $outFormat > 0;
    $mainTool->Options(List => 1) unless $joinLists;
    $showGroup = $allGroup = 1;         # always show group 1
    # set binaryOutput flag to 0 or undef (0 = output encoded binary in XML)
    $binaryOutput = ($outFormat > 0 ? undef : 0) if $binaryOutput;
    $showTagID = 'D' if $tabFormat and not $showTagID;
} elsif ($json) {
    if ($json == 1) { # JSON
        $fileHeader = '[';
        $fileTrailer = "]\n";
        undef $binaryOutput; # can't currently use -b with -json
    } else { # PHP
        $fileHeader = 'Array(';
        $fileTrailer = ");\n";
        # allow binary output in a text-mode file when -php and -b used together
        # (this works because PHP strings are simple arrays of bytes, and CR/LF
        #  won't be messed up in the text mode output because they are converted
        #  to escape sequences in the strings)
        $binaryOutput = 0 if $binaryOutput;
    }
    $mainTool->Options(List => 1) unless $joinLists;
    $mainTool->Options(Duplicates => 0) unless defined $showGroup;
} elsif ($structOpt) {
    $mainTool->Options(List => 1);
} else {
    $joinLists = 1;     # join lists for all other unstructured output formats
}

if ($argFormat) {
    $outFormat = 3;
    $allGroup = 1 if defined $showGroup;
}

# change to forward slashes if necessary in all filenames (like CleanFilename)
if ($hasBackslash{$^O}) {
    tr/\\/\// foreach @files;
}

# can't do anything if no file specified
unless (@files) {
    unless ($outOpt) {
        Warn "No file specified\n";
        $rtnVal = 1;
        next;
    }
    push @files, '';    # create file from nothing
}

# set Verbose and HtmlDump options
if ($verbose) {
    $disableOutput = 1 unless @tags or @exclude;
    undef $binaryOutput;    # disable conflicting option
    if ($html) {
        $html = 2;    # flag for html dump
        $mainTool->Options(HtmlDump => $verbose);
    } else {
        $mainTool->Options(Verbose => $verbose);
    }
} elsif (defined $verbose) {
    # auto-flush output when -v0 is used
    require FileHandle;
    STDOUT->autoflush(1);
    STDERR->autoflush(1);
}

# validate all tags we're writing
my $needSave = 1;
if (@newValues) {
    # assume -geotime value if -geotag specified without -geotime
    if ($addGeotime) {
        AddSetTagsFile($setTagsFile = '@') unless $setTagsFile and $setTagsFile eq '@';
        push @{$setTags{$setTagsFile}}, $addGeotime;
        $verbose and print qq{Argument "-$addGeotime" is assumed\n};
    }
    my %setTagsIndex;
    # add/delete option lookup
    my %addDelOpt = ( '+' => 'AddValue', '-' => 'DelValue', "\xe2\x88\x92" => 'DelValue' );
    $saveCount = 0;
    foreach (@newValues) {
        if (ref $_ eq 'HASH') {
            # save new values now if we stored a "SaveCount" marker
            if ($$_{SaveCount}) {
                $saveCount = $mainTool->SaveNewValues();
                $needSave = 0;
                # insert marker to load values from CSV file now if this was the CSV file
                push @dynamicFiles, \$csv if $$_{SaveCount} == $csvSaveCount;
            }
            next;
        }
        /(.*?)=(.*)/s or next;
        my ($tag, $newVal) = ($1, $2);
        $tag =~ s/\ball\b/\*/ig;    # replace 'all' with '*' in tag names
        $newVal eq '' and undef $newVal;    # undefined to delete tag
        if ($tag =~ /^(All)?TagsFromFile$/i) {
            defined $newVal or Error("Need file name for -tagsFromFile\n"), next Command;
            ++$isWriting;
            if ($newVal eq '@' or not defined FilenameSPrintf($newVal)) {
                push @dynamicFiles, $newVal;
                next;   # set tags from dynamic file later
            }
            unless (-e $newVal) {
                Warn "File '$newVal' does not exist for -tagsFromFile option\n";
                $rtnVal = 1;
                next Command;
            }
            my $setTags = $setTags{$newVal};
            # do we have multiple -tagsFromFile options with this file?
            if ($setTagsList{$newVal}) {
                # use the tags set in the i-th occurrence
                my $i = $setTagsIndex{$newVal} || 0;
                $setTagsIndex{$newVal} = $i + 1;
                $setTags = $setTagsList{$newVal}[$i] if $setTagsList{$newVal}[$i];
            }
            # set specified tags from this file
            unless (DoSetFromFile($mainTool, $newVal, $setTags)) {
                $rtnVal = 1;
                next Command;
            }
            $needSave = 1;
            next;
        }
        my %opts = (
            Protected => 1, # allow writing of 'unsafe' tags
            Shift => 0,     # shift values if possible instead of adding/deleting
        );
        if ($tag =~ s/<// and defined $newVal) {
            if (defined FilenameSPrintf($newVal)) {
                SlurpFile($newVal, \$newVal) or next;
            } else {
                $tag =~ s/([-+]|\xe2\x88\x92)$// and $opts{$addDelOpt{$1}} = 1;
                # verify that this tag can be written
                my $result = ExifTool::IsWritable($tag);
                if ($result) {
                    $opts{ProtectSaved} = $saveCount;   # protect new values set after this
                    # add to list of dynamic tag values
                    push @dynamicFiles, [ $tag, $newVal, \%opts ];
                    ++$isWriting;
                } elsif (defined $result) {
                    Warn "Tag '$tag' is not writable\n";
                } else {
                    Warn "Tag '$tag' does not exist\n";
                }
                next;
            }
        }
        if ($tag =~ s/([-+]|\xe2\x88\x92)$//) {
            $opts{$addDelOpt{$1}} = 1;  # set AddValue or DelValue option
            # set $newVal to '' if deleting nothing
            $newVal = '' if $1 eq '-' and not defined $newVal;
        }
        my ($rtn, $wrn) = $mainTool->SetNewValue($tag, $newVal, %opts);
        $needSave = 1;
        ++$isWriting if $rtn;
        $wrn and Warn "Warning: $wrn\n";
    }
    # exclude specified tags
    foreach (@exclude) {
        $mainTool->SetNewValue($_, undef, Replace => 2);
        $needSave = 1;
    }
    unless ($isWriting or $outOpt or @tags) {
        Warn "Nothing to do.\n";
        $rtnVal = 1;
        next;
    }
} elsif (grep /^(\*:)?\*$/, @exclude) {
    Warn "All tags excluded -- nothing to do.\n";
    $rtnVal = 1;
    next;
}
if ($isWriting and @tags and not $outOpt) {
    my ($tg, $s) = @tags > 1 ? ("$tags[0] ...", 's') : ($tags[0], '');
    Warn "Ignored superfluous tag name$s or invalid option$s: -$tg\n";
}
# save current state of new values if setting values from target file
# or if we may be translating to a different format
$mainTool->SaveNewValues() if $outOpt or (@dynamicFiles and $needSave);

$multiFile = 1 if @files > 1;
@exclude and $mainTool->Options(Exclude => \@exclude);

# set flag to fix description lengths if necessary
$fixLen = ($utf8 and $mainTool->Options('Lang') ne 'en' and eval 'require Encode');

# sort input files if specified
if (@fileOrder) {
    my @allFiles;
    ProcessFiles(undef, \@allFiles);
    my $sortTool = new ExifTool;
    $sortTool->Options(PrintConv => $mainTool->Options('PrintConv'));
    $sortTool->Options(Duplicates => 0);
    my (%sortBy, %isFloat, @rev, $file);
    # save reverse sort flags
    push @rev, (s/^-// ? 1 : 0) foreach @fileOrder;
    foreach $file (@allFiles) {
        my @tags;
        my $info = $sortTool->ImageInfo($file, @fileOrder, \@tags);
        # get values of all tags (or '~' to sort last if not defined)
        foreach (@tags) {
            $_ = $$info{$_};
            defined $_ or $_ = '~', next;
            $isFloat{$_} = 1 if /^[+-]?(?=\d|\.\d)\d*(\.\d*)?([Ee]([+-]?\d+))?$/;
        }
        $sortBy{$file} = \@tags;    # save tag values for each file
    }
    # sort in specified order
    @files = sort {
        my ($i, $cmp);
        for ($i=0; $i<@rev; ++$i) {
            my $u = $sortBy{$a}[$i];
            my $v = $sortBy{$b}[$i];
            if (not $isFloat{$u} and not $isFloat{$v}) {
                $cmp = $u cmp $v;               # alphabetically
            } elsif ($isFloat{$u} and $isFloat{$v}) {
                $cmp = $u <=> $v;               # numerically
            } else {
                $cmp = $isFloat{$u} ? -1 : 1;   # numbers first
            }
            return $rev[$i] ? -$cmp : $cmp if $cmp;
        }
        return $a cmp $b;   # default to sort by name
    } @allFiles;
} elsif (defined $progress) {
    # expand FILE argument to count the number of files to process
    my @allFiles;
    ProcessFiles(undef, \@allFiles);
    @files = @allFiles;
}
# set file count for progress message
$progressMax = scalar @files if defined $progress;

# store duplicate database information under canonical filenames
my @dbKeys = keys %database;
if (@dbKeys and require Cwd) {
    foreach (@dbKeys) {
        my $canonFile = Cwd::abs_path($_);
        if (defined $canonFile) {
            $database{$canonFile} = $database{$_} unless $database{$canonFile};
        } else {
            # (may happen on Mac if the filename encoding is incorrect in the database)
            Warn "Error generating canonical filename for $_\n";
        }
    }
}

# process all specified files
ProcessFiles($mainTool);

if ($filtered and not $validFile) {
    Warn "No file with specified extension\n";
    $rtnVal = 1;
}

# print file trailer if necessary
print $fileTrailer if $fileTrailer and not $textOut and not $fileHeader;

if (defined $deleteOrig) {

    # print summary and delete requested files
    unless ($quiet) {
        printf "%5d directories scanned\n", $countDir if $countDir;
        printf "%5d directories created\n", $countNewDir if $countNewDir;
        printf "%5d files failed condition\n", $countFailed if $countFailed;
        printf "%5d image files found\n", $count;
    }
    if (@delFiles) {
        # verify deletion unless "-delete_original!" was specified
        if ($deleteOrig == 1) {
            printf '%5d originals will be deleted!  Are you sure [y/n]? ', scalar(@delFiles);
            my $response = <STDIN>;
            unless ($response =~ /^(y|yes)\s*$/i) {
                Warn "Originals not deleted.\n";
                next;
            }
        }
        $countGoodWr = unlink @delFiles;
        $countBad = scalar(@delFiles) - $countGoodWr;
    }
    if ($quiet) {
        # no more messages
    } elsif ($count and not $countGoodWr and not $countBad) {
        printf "%5d original files found\n", $countGoodWr;
    } elsif ($deleteOrig) {
        printf "%5d original files deleted\n", $countGoodWr if $count;
        printf "%5d originals not deleted due to errors\n", $countBad if $countBad;
    } else {
        printf "%5d image files restored from original\n", $countGoodWr if $count;
        printf "%5d files not restored due to errors\n", $countBad if $countBad;
    }

} elsif (not $binaryStdout and not $quiet) {

}

# set error status if we had any errors or if all files failed the "-if" condition
$rtnVal = 1 if $countBadWr or $countBadCr or $countBad or ($countFailed and not $count);

# last ditch effort to preserve filemodifydate
PreserveTime() if %preserveTime;

} # end "Command" loop ........................................................

close STAYOPEN if $stayOpen >= 2;

Exit $rtnVal;   # all done


#------------------------------------------------------------------------------
# Get image information from EXIF data in file
# Inputs: 0) ExifTool object reference, 1) file name
sub GetImageInfo($$)
{
    my ($exifTool, $orig) = @_;
    my (@foundTags, $info, $file, $ind);

    # determine the name of the source file based on the original input file name
    if (@srcFmt) {
        my ($fmt, $first);
        foreach $fmt (@srcFmt) {
            $file = $fmt eq '@' ? $orig : FilenameSPrintf($fmt, $orig);
            # use this file if it exists
            -e $file and undef($first), last;
            $verbose and print "Source file $file does not exist\n";
            $first = $file unless defined $first;
        }
        $file = $first if defined $first;
    } else {
        $file = $orig;
    }
    printf("%s:", $file);

    my $pipe = $file;
    if ($doUnzip) {
        # pipe through gzip or bzip2 if necessary
        if ($file =~ /\.gz$/i) {
            $pipe = qq{gzip -dc "$file" |};
        } elsif ($file =~ /\.bz2$/i) {
            $pipe = qq{bzip2 -dc "$file" |};
        }
    }
    # evaluate -if expression for conditional processing
    if (defined $condition) {
        unless ($file eq '-' or -e $file) {
            Warn "File not found: $file\n";
            ++$countBad;
            return;
        }
        # catch run time errors as well as compile errors
        undef $evalWarning;
        local $SIG{'__WARN__'} = sub { $evalWarning = $_[0] };

        my %info;
        # extract information and build expression for evaluation
        my $opts = { Duplicates => 1, Verbose => 0, HtmlDump => 0 };
        # return all tags but explicitly mention tags on command line so
        # requested images will generate the appropriate warnings
        @foundTags = ('*', @tags) if @tags;
        $info = $exifTool->ImageInfo($pipe, \@foundTags, $opts);
        my $cond = $exifTool->InsertTagValues(\@foundTags, $condition, \%info);

        #### eval "-if" condition (%info)
        my $result = eval $cond;

        $@ and $evalWarning = $@;
        if ($evalWarning) {
            # fail condition if warning is issued
            undef $result;
            if ($verbose) {
                chomp $evalWarning;
                $evalWarning =~ s/ at \(eval .*//s;
                delete $SIG{'__WARN__'};
                Warn "Condition: $evalWarning - $file\n";
            }
        }
        unless ($result) {
            $verbose and print "-------- $file (failed condition)$progStr\n";
            ++$countFailed;
            return;
        }
        # can't make use of $info if verbose because we must reprocess
        # the file anyway to generate the verbose output
        undef $info if $verbose;
    }
    if (defined $deleteOrig) {
        #print "======== $file$progStr\n" if defined $verbose;
        ++$count;
        my $original = "${file}_original";
        -e $original or return;
        if ($deleteOrig) {
            $verbose and print "Scheduled for deletion: $original\n";
            push @delFiles, $original;
        } elsif (rename $original, $file) {
            $verbose and print "Restored from $original\n";
            ++$countGoodWr;
        } else {
            Warn "Error renaming $original\n";
            ++$countBad;
        }
        return;
    }
    my $lineCount = 0;
    my ($fp, $outfile);
    #if ($textOut and $verbose) {
    #    ($fp, $outfile) = OpenOutputFile($orig);
    #    $fp or ++$countBad, return;
    #    $tmpText = $outfile;    # deletes file if we exit prematurely
    #    $exifTool->Options(TextOut => $fp);
    #}

    if ($isWriting) {
        #print "======== $file$progStr\n" if defined $verbose;
        SetImageInfo($exifTool, $file, $orig);
        $info = $exifTool->GetInfo('Warning', 'Error');
        PrintErrors($exifTool, $info, $file);
        # close output text file if necessary
        if ($outfile) {
            undef $tmpText;
            close($fp);
            $exifTool->Options(TextOut => \*STDOUT);
            if ($info->{Error}) {
                unlink $outfile;    # erase bad file
            } else {
                ++$countCreated;
            }
        }
        return;
    }

    # extract information from this file
    unless ($file eq '-' or -e $file) {
        Warn "File not found: $file\n";
        $outfile and close($fp), undef($tmpText), unlink($outfile);
        ++$countBad;
        return;
    }
    # print file/progress message
    my $o;
    unless ($binaryOutput or $textOut or %printFmt or $html > 1 or $csv) {
        if ($html) {
            require ExifTool::HTML;
            my $f = ExifTool::HTML::EscapeHTML($file);
            print "<!-- $f -->\n";
        } elsif (not ($json or $xml)) {
            $o = \*STDOUT if ($multiFile and not $quiet) or $progress;
        }
    }
    $o = \*STDERR if $progress and not $o;
    #$o and print $o "======== $file$progStr\n";
    if ($info) {
        # get the information we wanted
        if (@tags and not %printFmt) {
            @foundTags = @tags;
            $info = $exifTool->GetInfo(\@foundTags);
        }
    } else {
        # request specified tags unless using print format option
        my $oldDups = $exifTool->Options('Duplicates');
        if (%printFmt) {
            $exifTool->Options(Duplicates => 1);
        } else {
            @foundTags = @tags;
        }
        # extract the information
        $info = $exifTool->ImageInfo($pipe, \@foundTags);
        $exifTool->Options(Duplicates => $oldDups);
    }
    # all done now if we already wrote output text file (ie. verbose option)
    if ($fp) {
        if ($outfile) {
            $exifTool->Options(TextOut => \*STDOUT);
            undef $tmpText;
            if ($info->{Error}) {
                close($fp);
                unlink $outfile;    # erase bad file
            } else {
                ++$lineCount;       # output text file (likely) is not empty
            }
        }
        if ($info->{Error}) {
            Warn "Error: $info->{Error} - $file\n";
            ++$countBad;
            return;
        }
    }

    # print warnings to stderr if using binary output
    # (because we are likely ignoring them and piping stdout to file)
    # or if there is none of the requested information available
    if ($binaryOutput or not %$info) {
        my $errs = $exifTool->GetInfo('Warning', 'Error');
        PrintErrors($exifTool, $errs, $file);
    }

    ++$count;
}

#------------------------------------------------------------------------------
# Translate backslashes to forward slashes in filename if necessary
# Inputs: 0) Filename
# Returns: nothing, but changes filename if necessary
sub CleanFilename($)
{
    $_[0] =~ tr/\\/\// if $hasBackslash{$^O};
}

#------------------------------------------------------------------------------
# process files in our @files list
# Inputs: 0) ExifTool ref, 1) list ref to just return full file names
# Notes: arg 0 is not used if arg 1 is defined
sub ProcessFiles($;$)
{
    my ($exifTool, $list) = @_;
    my $file;
    foreach $file (@files) {
        if (defined $progressMax) {
            ++$progress;
            $progStr = " [$progress/$progressMax]";
        }
        if (-d $file) {
            $multiFile = $validFile = 1;
            ScanDir($mainTool, $file, $list);
        } elsif ($filterFlag and not AcceptFile($file)) {
            if (-e $file) {
                $filtered = 1;
                $verbose and print "-------- $file (wrong extension)$progStr\n";
            } else {
                Warn "File not found: $file\n";
                $rtnVal = 1;
            }
        } else {
            $validFile = 1;
            $list and push(@$list, $file), next;
            GetImageInfo($exifTool, $file);
        }
    }
}
